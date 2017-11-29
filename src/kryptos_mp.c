/*
 *                                Copyright (C) 2017 by Rafael Santiago
 *
 * This is a free software. You can redistribute it and/or modify under
 * the terms of the GNU General Public License version 2.
 *
 */

// 'Hexadecimals. Hexadecimals to the rescue.'
//              -- Mark Watney (The Martian)

#include <kryptos_mp.h>
#include <kryptos_memory.h>
#include <kryptos_random.h>
#ifndef KRYPTOS_KERNEL_MODE
# include <string.h>
# include <ctype.h>
# include <stdio.h>
//# include <inttypes.h>
#else
# include <kryptos_userland_funcs.h>
#endif

#define kryptos_mp_xnb(n) ( isdigit((n)) ? ( (n) - 48 ) : ( toupper((n)) - 55 )  )

static kryptos_u8_t nbxlt[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'
};

#define kryptos_mp_nbx(x) ( nbxlt[(x)] )

#define kryptos_mp_max_min(aa, bb, a, b) {\
    if ((a)->data_size >= (b)->data_size) {\
        (aa) = (a);\
        (bb) = (b);\
    } else {\
        (aa) = (b);\
        (bb) = (a);\
    }\
}

#define KRYPTOS_MP_MULTIBYTE_FLOOR 4

#define kryptos_mp_get_u32_from_mp(m, i) ( ((i) < (m)->data_size) ? ( (kryptos_u32_t)((m)->data[(i) + 3] << 24) |\
                                                                      (kryptos_u32_t)((m)->data[(i) + 2] << 16) |\
                                                                      (kryptos_u32_t)((m)->data[(i) + 1] <<  8) |\
                                                                      (kryptos_u32_t)((m)->data[  (i)  ]) ) : 0 )

#define kryptos_mp_put_u32_into_mp(m, i, v) {\
    (m)->data[(i) + 3] = (v) >> 24;\
    (m)->data[(i) + 2] = ((v) >> 16) & 0xFF;\
    (m)->data[(i) + 1] = ((v) >>  8) & 0xFF;\
    (m)->data[  (i)  ] = (v) & 0xFF;\
}

#define KRYPTOS_MP_ABORT_WHEN_NULL(stmt, escape) {\
    if ((stmt) == NULL) {\
        goto escape;\
    }\
}

static char *g_kryptos_mp_small_primes[] = {
    "0003", "0005", "0007", "000B", "000D", "0011", "0013", "0017", "001D", "001F", "0025", "0029", "002B", "002F", "0035",
    "003B", "003D", "0043", "0047", "0049", "004F", "0053", "0059", "0061", "0065", "0067", "006B", "006D", "0071", "007F",
    "0083", "0089", "008B", "0095", "0097", "009D", "00A3", "00A7", "00AD", "00B3", "00B5", "00BF", "00C1", "00C5", "00C7",
    "00D3", "00DF", "00E3", "00E5", "00E9", "00EF", "00F1", "00FB", "0101", "0107", "010D", "010F", "0115", "0119", "011B",
    "0125", "0133", "0137", "0139", "013D", "014B", "0151", "015B", "015D", "0161", "0167", "016F", "0175", "017B", "017F",
    "0185", "018D", "0191", "0199", "01A3", "01A5", "01AF", "01B1", "01B7", "01BB", "01C1", "01C9", "01CD", "01CF", "01D3",
    "01DF", "01E7", "01EB", "01F3", "01F7", "01FD", "0209", "020B", "021D", "0223", "022D", "0233", "0239", "023B", "0241",
    "024B", "0251", "0257", "0259", "025F", "0265", "0269", "026B", "0277", "0281", "0283", "0287", "028D", "0293", "0295",
    "02A1", "02A5", "02AB", "02B3", "02BD", "02C5", "02CF", "02D7", "02DD", "02E3", "02E7", "02EF", "02F5", "02F9", "0301",
    "0305", "0313", "031D", "0329", "032B", "0335", "0337", "033B", "033D", "0347", "0355", "0359", "035B", "035F", "036D",
    "0371", "0373", "0377", "038B", "038F", "0397", "03A1", "03A9", "03AD", "03B3", "03B9", "03C7", "03CB", "03D1", "03D7",
    "03DF", "03E5", "03F1", "03F5", "03FB", "03FD", "0407", "0409", "040F", "0419", "041B", "0425", "0427", "042D", "043F",
    "0443", "0445", "0449", "044F", "0455", "045D", "0463", "0469", "047F", "0481", "048B", "0493", "049D", "04A3", "04A9",
    "04B1", "04BD", "04C1", "04C7", "04CD", "04CF", "04D5", "04E1", "04EB", "04FD", "04FF", "0503", "0509", "050B", "0511",
    "0515", "0517", "051B", "0527", "0529", "052F", "0551", "0557", "055D", "0565", "0577", "0581", "058F", "0593", "0595",
    "0599", "059F", "05A7", "05AB", "05AD", "05B3", "05BF", "05C9", "05CB", "05CF", "05D1", "05D5", "05DB", "05E7", "05F3",
    "05FB", "0607", "060D", "0611", "0617", "061F", "0623", "062B", "062F", "063D", "0641", "0647", "0649", "064D", "0653",
    "0655", "065B", "0665", "0679", "067F", "0683", "0685", "069D", "06A1", "06A3", "06AD", "06B9", "06BB", "06C5", "06CD",
    "06D3", "06D9", "06DF", "06F1", "06F7", "06FB", "06FD", "0709", "0713", "071F", "0727", "0737", "0745", "074B", "074F",
    "0751", "0755", "0757", "0761", "076D", "0773", "0779", "078B", "078D", "079D", "079F", "07B5", "07BB", "07C3", "07C9",
    "07CD", "07CF", "07D3", "07DB", "07E1", "07EB", "07ED", "07F7", "0805", "080F", "0815", "0821", "0823", "0827", "0829",
    "0833", "083F", "0841", "0851", "0853", "0859", "085D", "085F", "0869", "0871", "0883", "089B", "089F", "08A5", "08AD",
    "08BD", "08BF", "08C3", "08CB", "08DB", "08DD", "08E1", "08E9", "08EF", "08F5", "08F9", "0905", "0907", "091D", "0923",
    "0925", "092B", "092F", "0935", "0943", "0949", "094D", "094F", "0955", "0959", "095F", "096B", "0971", "0977", "0985",
    "0989", "098F", "099B", "09A3", "09A9", "09AD", "09C7", "09D9", "09E3", "09EB", "09EF", "09F5", "09F7", "09FD", "0A13",
    "0A1F", "0A21", "0A31", "0A39", "0A3D", "0A49", "0A57", "0A61", "0A63", "0A67", "0A6F", "0A75", "0A7B", "0A7F", "0A81",
    "0A85", "0A8B", "0A93", "0A97", "0A99", "0A9F", "0AA9", "0AAB", "0AB5", "0ABD", "0AC1", "0ACF", "0AD9", "0AE5", "0AE7",
    "0AED", "0AF1", "0AF3", "0B03", "0B11", "0B15", "0B1B", "0B23", "0B29", "0B2D", "0B3F", "0B47", "0B51", "0B57", "0B5D",
    "0B65", "0B6F", "0B7B", "0B89", "0B8D", "0B93", "0B99", "0B9B", "0BB7", "0BB9", "0BC3", "0BCB", "0BCF", "0BDD", "0BE1",
    "0BE9", "0BF5", "0BFB", "0C07", "0C0B", "0C11", "0C25", "0C2F", "0C31", "0C41", "0C5B", "0C5F", "0C61", "0C6D", "0C73",
    "0C77", "0C83", "0C89", "0C91", "0C95", "0C9D", "0CB3", "0CB5", "0CB9", "0CBB", "0CC7", "0CE3", "0CE5", "0CEB", "0CF1",
    "0CF7", "0CFB", "0D01", "0D03", "0D0F", "0D13", "0D1F", "0D21", "0D2B", "0D2D", "0D3D", "0D3F", "0D4F", "0D55", "0D69",
    "0D79", "0D81", "0D85", "0D87", "0D8B", "0D8D", "0DA3", "0DAB", "0DB7", "0DBD", "0DC7", "0DC9", "0DCD", "0DD3", "0DD5",
    "0DDB", "0DE5", "0DE7", "0DF3", "0DFD", "0DFF", "0E09", "0E17", "0E1D", "0E21", "0E27", "0E2F", "0E35", "0E3B", "0E4B",
    "0E57", "0E59", "0E5D", "0E6B", "0E71", "0E75", "0E7D", "0E87", "0E8F", "0E95", "0E9B", "0EB1", "0EB7", "0EB9", "0EC3",
    "0ED1", "0ED5", "0EDB", "0EED", "0EEF", "0EF9", "0F07", "0F0B", "0F0D", "0F17", "0F25", "0F29", "0F31", "0F43", "0F47",
    "0F4D", "0F4F", "0F53", "0F59", "0F5B", "0F67", "0F6B", "0F7F", "0F95", "0FA1", "0FA3", "0FA7", "0FAD", "0FB3", "0FB5",
    "0FBB", "0FD1", "0FD3", "0FD9", "0FE9", "0FEF", "0FFB", "0FFD", "1003", "100F", "101F", "1021", "1025", "102B", "1039",
    "103D", "103F", "1051", "1069", "1073", "1079", "107B", "1085", "1087", "1091", "1093", "109D", "10A3", "10A5", "10AF",
    "10B1", "10BB", "10C1", "10C9", "10E7", "10F1", "10F3", "10FD", "1105", "110B", "1115", "1127", "112D", "1139", "1145",
    "1147", "1159", "115F", "1163", "1169", "116F", "1181", "1183", "118D", "119B", "11A1", "11A5", "11A7", "11AB", "11C3",
    "11C5", "11D1", "11D7", "11E7", "11EF", "11F5", "11FB", "120D", "121D", "121F", "1223", "1229", "122B", "1231", "1237",
    "1241", "1247", "1253", "125F", "1271", "1273", "1279", "127D", "128F", "1297", "12AF", "12B3", "12B5", "12B9", "12BF",
    "12C1", "12CD", "12D1", "12DF", "12FD", "1307", "130D", "1319", "1327", "132D", "1337", "1343", "1345", "1349", "134F",
    "1357", "135D", "1367", "1369", "136D", "137B", "1381", "1387", "138B", "1391", "1393", "139D", "139F", "13AF", "13BB",
    "13C3", "13D5", "13D9", "13DF", "13EB", "13ED", "13F3", "13F9", "13FF", "141B", "1421", "142F", "1433", "143B", "1445",
    "144D", "1459", "146B", "146F", "1471", "1475", "148D", "1499", "149F", "14A1", "14B1", "14B7", "14BD", "14CB", "14D5",
    "14E3", "14E7", "1505", "150B", "1511", "1517", "151F", "1525", "1529", "152B", "1537", "153D", "1541", "1543", "1549",
    "155F", "1565", "1567", "156B", "157D", "157F", "1583", "158F", "1591", "1597", "159B", "15B5", "15BB", "15C1", "15C5",
    "15CD", "15D7", "15F7", "1607", "1609", "160F", "1613", "1615", "1619", "161B", "1625", "1633", "1639", "163D", "1645",
    "164F", "1655", "1669", "166D", "166F", "1675", "1693", "1697", "169F", "16A9", "16AF", "16B5", "16BD", "16C3", "16CF",
    "16D3", "16D9", "16DB", "16E1", "16E5", "16EB", "16ED", "16F7", "16F9", "1709", "170F", "1723", "1727", "1733", "1741",
    "175D", "1763", "1777", "177B", "178D", "1795", "179B", "179F", "17A5", "17B3", "17B9", "17BF", "17C9", "17CB", "17D5",
    "17E1", "17E9", "17F3", "17F5", "17FF", "1807", "1813", "181D", "1835", "1837", "183B", "1843", "1849", "184D", "1855",
    "1867", "1871", "1877", "187D", "187F", "1885", "188F", "189B", "189D", "18A7", "18AD", "18B3", "18B9", "18C1", "18C7",
    "18D1", "18D7", "18D9", "18DF", "18E5", "18EB", "18F5", "18FD", "1915", "191B", "1931", "1933", "1945", "1949", "1951",
    "195B", "1979", "1981", "1993", "1997", "1999", "19A3", "19A9", "19AB", "19B1", "19B5", "19C7", "19CF", "19DB", "19ED",
    "19FD", "1A03", "1A05", "1A11", "1A17", "1A21", "1A23", "1A2D", "1A2F", "1A35", "1A3F", "1A4D", "1A51", "1A69", "1A6B",
    "1A7B", "1A7D", "1A87", "1A89", "1A93", "1AA7", "1AAB", "1AAD", "1AB1", "1AB9", "1AC9", "1ACF", "1AD5", "1AD7", "1AE3",
    "1AF3", "1AFB", "1AFF", "1B05", "1B23", "1B25", "1B2F", "1B31", "1B37", "1B3B", "1B41", "1B47", "1B4F", "1B55", "1B59",
    "1B65", "1B6B", "1B73", "1B7F", "1B83", "1B91", "1B9D", "1BA7", "1BBF", "1BC5", "1BD1", "1BD7", "1BD9", "1BEF", "1BF7",
    "1C09", "1C13", "1C19", "1C27", "1C2B", "1C2D", "1C33", "1C3D", "1C45", "1C4B", "1C4F", "1C55", "1C73", "1C81", "1C8B",
    "1C8D", "1C99", "1CA3", "1CA5", "1CB5", "1CB7", "1CC9", "1CE1", "1CF3", "1CF9", "1D09", "1D1B", "1D21", "1D23", "1D35",
    "1D39", "1D3F", "1D41", "1D4B", "1D53", "1D5D", "1D63", "1D69", "1D71", "1D75", "1D7B", "1D7D", "1D87", "1D89", "1D95",
    "1D99", "1D9F", "1DA5", "1DA7", "1DB3", "1DB7", "1DC5", "1DD7", "1DDB", "1DE1", "1DF5", "1DF9", "1E01", "1E07", "1E0B",
    "1E13", "1E17", "1E25", "1E2B", "1E2F", "1E3D", "1E49", "1E4D", "1E4F", "1E6D", "1E71", "1E89", "1E8F", "1E95", "1EA1",
    "1EAD", "1EBB", "1EC1", "1EC5", "1EC7", "1ECB", "1EDD", "1EE3", "1EEF", "1EF7", "1EFD", "1F01", "1F0D", "1F0F", "1F1B",
    "1F39", "1F49", "1F4B", "1F51", "1F67", "1F75", "1F7B", "1F85", "1F91", "1F97", "1F99", "1F9D", "1FA5", "1FAF", "1FB5",
    "1FBB", "1FD3", "1FE1", "1FE7", "1FEB", "1FF3", "1FFF", "2011", "201B", "201D", "2027", "2029", "202D", "2033", "2047",
    "204D", "2051", "205F", "2063", "2065", "2069", "2077", "207D", "2089", "20A1", "20AB", "20B1", "20B9", "20C3", "20C5",
    "20E3", "20E7", "20ED", "20EF", "20FB", "20FF", "210D", "2113", "2135", "2141", "2149", "214F", "2159", "215B", "215F",
    "2173", "217D", "2185", "2195", "2197", "21A1", "21AF", "21B3", "21B5", "21C1", "21C7", "21D7", "21DD", "21E5", "21E9",
    "21F1", "21F5", "21FB", "2203", "2209", "220F", "221B", "2221", "2225", "222B", "2231", "2239", "224B", "224F", "2263",
    "2267", "2273", "2275", "227F", "2285", "2287", "2291", "229D", "229F", "22A3", "22B7", "22BD", "22DB", "22E1", "22E5",
    "22ED", "22F7", "2303", "2309", "230B", "2327", "2329", "232F", "2333", "2335", "2345", "2351", "2353", "2359", "2363",
    "236B", "2383", "238F", "2395", "23A7", "23AD", "23B1", "23BF", "23C5", "23C9", "23D5", "23DD", "23E3", "23EF", "23F3",
    "23F9", "2405", "240B", "2417", "2419", "2429", "243D", "2441", "2443", "244D", "245F", "2467", "246B", "2479", "247D",
    "247F", "2485", "249B", "24A1", "24AF", "24B5", "24BB", "24C5", "24CB", "24CD", "24D7", "24D9", "24DD", "24DF", "24F5",
    "24F7", "24FB", "2501", "2507", "2513", "2519", "2527", "2531", "253D", "2543", "254B", "254F", "2573", "2581", "258D",
    "2593", "2597", "259D", "259F", "25AB", "25B1", "25BD", "25CD", "25CF", "25D9", "25E1", "25F7", "25F9", "2605", "260B",
    "260F", "2615", "2627", "2629", "2635", "263B", "263F", "264B", "2653", "2659", "2665", "2669", "266F", "267B", "2681",
    "2683", "268F", "269B", "269F", "26AD", "26B3", "26C3", "26C9", "26CB", "26D5", "26DD", "26EF", "26F5", "2717", "2719",
    "2735", "2737", "274D", "2753", "2755", "275F", "276B", "276D", "2773", "2777", "277F", "2795", "279B", "279D", "27A7",
    "27AF", "27B3", "27B9", "27C1", "27C5", "27D1", "27E3", "27EF", "2803", "2807", "280D", "2813", "281B", "281F", "2821",
    "2831", "283D", "283F", "2849", "2851", "285B", "285D", "2861", "2867", "2875", "2881", "2897", "289F", "28BB", "28BD",
    "28C1", "28D5", "28D9", "28DB", "28DF", "28ED", "28F7", "2903", "2905", "2911", "2921", "2923", "293F", "2947", "295D",
    "2965", "2969", "296F", "2975", "2983", "2987", "298F", "299B", "29A1", "29A7", "29AB", "29BF", "29C3", "29D5", "29D7",
    "29E3", "29E9", "29ED", "29F3", "2A01", "2A13", "2A1D", "2A25", "2A2F", "2A4F", "2A55", "2A5F", "2A65", "2A6B", "2A6D",
    "2A73", "2A83", "2A89", "2A8B", "2A97", "2A9D", "2AB9", "2ABB", "2AC5", "2ACD", "2ADD", "2AE3", "2AEB", "2AF1", "2AFB",
    "2B13", "2B27", "2B31", "2B33", "2B3D", "2B3F", "2B4B", "2B4F", "2B55", "2B69", "2B6D", "2B6F", "2B7B", "2B8D", "2B97",
    "2B99", "2BA3", "2BA5", "2BA9", "2BBD", "2BCD", "2BE7", "2BEB", "2BF3", "2BF9", "2BFD", "2C09", "2C0F", "2C17", "2C23",
    "2C2F", "2C35", "2C39", "2C41", "2C57", "2C59", "2C69", "2C77", "2C81", "2C87", "2C93", "2C9F", "2CAD", "2CB3", "2CB7",
    "2CCB", "2CCF", "2CDB", "2CE1", "2CE3", "2CE9", "2CEF", "2CFF", "2D07", "2D1D", "2D1F", "2D3B", "2D43", "2D49", "2D4D",
    "2D61", "2D65", "2D71", "2D89", "2D9D", "2DA1", "2DA9", "2DB3", "2DB5", "2DC5", "2DC7", "2DD3", "2DDF", "2E01", "2E03",
    "2E07", "2E0D", "2E19", "2E1F", "2E25", "2E2D", "2E33", "2E37", "2E39", "2E3F", "2E57", "2E5B", "2E6F", "2E79", "2E7F",
    "2E85", "2E93", "2E97", "2E9D", "2EA3", "2EA5", "2EB1", "2EB7", "2EC1", "2EC3", "2ECD", "2ED3", "2EE7", "2EEB", "2F05",
    "2F09", "2F0B", "2F11", "2F27", "2F29", "2F41", "2F45", "2F4B", "2F4D", "2F51", "2F57", "2F6F", "2F75", "2F7D", "2F81",
    "2F83", "2FA5", "2FAB", "2FB3", "2FC3", "2FCF", "2FD1", "2FDB", "2FDD", "2FE7", "2FED", "2FF5", "2FF9", "3001", "300D",
    "3023", "3029", "3037", "303B", "3055", "3059", "305B", "3067", "3071", "3079", "307D", "3085", "3091", "3095", "30A3",
    "30A9", "30B9", "30BF", "30C7", "30CB", "30D1", "30D7", "30DF", "30E5", "30EF", "30FB", "30FD", "3103", "3109", "3119",
    "3121", "3127", "312D", "3139", "3143", "3145", "314B", "315D", "3161", "3167", "316D", "3173", "317F", "3191", "3199",
    "319F", "31A9", "31B1", "31C3", "31C7", "31D5", "31DB", "31ED", "31F7", "31FF", "3209", "3215", "3217", "321D", "3229",
    "3235", "3259", "325D", "3263", "326B", "326F", "3275", "3277", "327B", "328D", "3299", "329F", "32A7", "32AD", "32B3",
    "32B7", "32C9", "32CB", "32CF", "32D1", "32E9", "32ED", "32F3", "32F9", "3307", "3325", "332B", "332F", "3335", "3341",
    "3347", "335B", "335F", "3367", "336B", "3373", "3379", "337F", "3383", "33A1", "33A3", "33AD", "33B9", "33C1", "33CB",
    "33D3", "33EB", "33F1", "33FD", "3401", "340F", "3413", "3419", "341B", "3437", "3445", "3455", "3457", "3463", "3469",
    "346D", "3481", "348B", "3491", "3497", "349D", "34A5", "34AF", "34BB", "34C9", "34D3", "34E1", "34F1", "34FF", "3509",
    "3517", "351D", "352D", "3533", "353B", "3541", "3551", "3565", "356F", "3571", "3577", "357B", "357D", "3581", "358D",
    "358F", "3599", "359B", "35A1", "35B7", "35BD", "35BF", "35C3", "35D5", "35DD", "35E7", "35EF", "3605", "3607", "3611",
    "3623", "3631", "3635", "3637", "363B", "364D", "364F", "3653", "3659", "3661", "366B", "366D", "368B", "368F", "36AD",
    "36AF", "36B9", "36BB", "36CD", "36D1", "36E3", "36E9", "36F7", "3701", "3703", "3707", "371B", "373F", "3745", "3749",
    "374F", "375D", "3761", "3775", "377F", "378D", "37A3", "37A9", "37AB", "37C9", "37D5", "37DF", "37F1", "37F3", "37F7",
    "3805", "380B", "3821", "3833", "3835", "3841", "3847", "384B", "3853", "3857", "385F", "3865", "386F", "3871", "387D",
    "388F", "3899", "38A7", "38B7", "38C5", "38C9", "38CF", "38D5", "38D7", "38DD", "38E1", "38E3", "38FF", "3901", "391D",
    "3923", "3925", "3929", "392F", "393D", "3941", "394D", "395B", "396B", "3979", "397D", "3983", "398B", "3991", "3995",
    "399B", "39A1", "39A7", "39AF", "39B3", "39BB", "39BF", "39CD", "39DD", "39E5", "39EB", "39EF", "39FB", "3A03", "3A13",
    "3A15", "3A1F", "3A27", "3A2B", "3A31", "3A4B", "3A51", "3A5B", "3A63", "3A67", "3A6D", "3A79", "3A87", "3AA5", "3AA9",
    "3AB7", "3ACD", "3AD5", "3AE1", "3AE5", "3AEB", "3AF3", "3AFD", "3B03", "3B11", "3B1B", "3B21", "3B23", "3B2D", "3B39",
    "3B45", "3B53", "3B59", "3B5F", "3B71", "3B7B", "3B81", "3B89", "3B9B", "3B9F", "3BA5", "3BA7", "3BAD", "3BB7", "3BB9",
    "3BC3", "3BCB", "3BD1", "3BD7", "3BE1", "3BE3", "3BF5", "3BFF", "3C01", "3C0D", "3C11", "3C17", "3C1F", "3C29", "3C35",
    "3C43", "3C4F", "3C53", "3C5B", "3C65", "3C6B", "3C71", "3C85", "3C89", "3C97", "3CA7", "3CB5", "3CBF", "3CC7", "3CD1",
    "3CDD", "3CDF", "3CF1", "3CF7", "3D03", "3D0D", "3D19", "3D1B", "3D1F", "3D21", "3D2D", "3D33", "3D37", "3D3F", "3D43",
    "3D6F", "3D73", "3D75", "3D79", "3D7B", "3D85", "3D91", "3D97", "3D9D", "3DAB", "3DAF", "3DB5", "3DBB", "3DC1", "3DC9",
    "3DCF", "3DF3", "3E05", "3E09", "3E0F", "3E11", "3E1D", "3E23", "3E29", "3E2F", "3E33", "3E41", "3E57", "3E63", "3E65",
    "3E77", "3E81", "3E87", "3EA1", "3EB9", "3EBD", "3EBF", "3EC3", "3EC5", "3EC9", "3ED7", "3EDB", "3EE1", "3EE7", "3EEF",
    "3EFF", "3F0B", "3F0D", "3F37", "3F3B", "3F3D", "3F41", "3F59", "3F5F", "3F65", "3F67", "3F79", "3F7D", "3F8B", "3F91",
    "3FAD", "3FBF", "3FCD", "3FD3", "3FDD", "3FE9", "3FEB", "3FF1", "3FFD", "401B", "4021", "4025", "402B", "4031", "403F",
    "4043", "4045", "405D", "4061", "4067", "406D", "4087", "4091", "40A3", "40A9", "40B1", "40B7", "40BD", "40DB", "40DF",
    "40EB", "40F7", "40F9", "4109", "410B", "4111", "4115", "4121", "4133", "4135", "413B", "413F", "4159", "4165", "416B",
    "4177", "417B", "4193", "41AB", "41B7", "41BD", "41BF", "41CB", "41E7", "41EF", "41F3", "41F9", "4205", "4207", "4219",
    "421F", "4223", "4229", "422F", "4243", "4253", "4255", "425B", "4261", "4273", "427D", "4283", "4285", "4289", "4291",
    "4297", "429D", "42B5", "42C5", "42CB", "42D3", "42DD", "42E3", "42F1", "4307", "430F", "431F", "4325", "4327", "4333",
    "4337", "4339", "434F", "4357", "4369", "438B", "438D", "4393", "43A5", "43A9", "43AF", "43B5", "43BD", "43C7", "43CF",
    "43E1", "43E7", "43EB", "43ED", "43F1", "43F9", "4409", "440B", "4417", "4423", "4429", "443B", "443F", "4445", "444B",
    "4451", "4453", "4459", "4465", "446F", "4483", "448F", "44A1", "44A5", "44AB", "44AD", "44BD", "44BF", "44C9", "44D7",
    "44DB", "44F9", "44FB", "4505", "4511", "4513", "452B", "4531", "4541", "4549", "4553", "4555", "4561", "4577", "457D",
    "457F", "458F", "45A3", "45AD", "45AF", "45BB", "45C7"
};

static size_t g_kryptos_mp_small_primes_nr = sizeof(g_kryptos_mp_small_primes) / sizeof(g_kryptos_mp_small_primes[0]);

#ifndef KRYPTOS_MP_U32_DIGIT

static kryptos_mp_value_t *kryptos_mp_pad_for_multibyte(const kryptos_mp_value_t *v);

static kryptos_mp_value_t *kryptos_mp_multibyte_add(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b);

static kryptos_mp_value_t *kryptos_mp_multibyte_mul(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b);

#endif

static kryptos_mp_value_t *kryptos_mp_montgomery_reduction_2kx_mod_y(const kryptos_mp_value_t *x,
                                                                     const kryptos_mp_value_t *y);

static int kryptos_mp_gen_prime_small_primes_test(const kryptos_mp_value_t *n, kryptos_mp_value_t **prime);

kryptos_mp_value_t *kryptos_new_mp_value(const size_t bitsize) {
    kryptos_mp_value_t *mp;

    mp = (kryptos_mp_value_t *) kryptos_newseg(sizeof(kryptos_mp_value_t));

    if (mp == NULL) {
        return NULL;
    }

    mp->data_size = bitsize;

    while (mp->data_size < 8) {
        mp->data_size++;
    }

    while ((mp->data_size % (sizeof(kryptos_mp_digit_t) << 3)) != 0) {
        mp->data_size++;
    }

    mp->data_size = kryptos_mp_bit2byte(mp->data_size);

    if (mp->data_size == 0) {
        mp->data_size = 1;
    }

    mp->data = (kryptos_mp_digit_t *) kryptos_newseg(mp->data_size * sizeof(kryptos_mp_digit_t));
    memset(mp->data, 0, mp->data_size * sizeof(kryptos_mp_digit_t));

    return mp;
}

void kryptos_del_mp_value(kryptos_mp_value_t *mp) {
    if (mp == NULL) {
        return;
    }

    if (mp->data != NULL) {
        memset(mp->data, 0, mp->data_size);
        kryptos_freeseg(mp->data);
        mp->data_size = 0;
    }

    kryptos_freeseg(mp);
}

kryptos_mp_value_t *kryptos_assign_mp_value(kryptos_mp_value_t **dest,
                                            const kryptos_mp_value_t *src) {
    ssize_t d;

    if (src == NULL || dest == NULL) {
        return NULL;
    }

    if ((*dest) == NULL) {
        (*dest) = kryptos_new_mp_value(src->data_size << 3);
    }

    if (src->data_size > (*dest)->data_size) {
        kryptos_freeseg((*dest)->data);
        (*dest)->data_size = src->data_size;
        (*dest)->data = (kryptos_mp_digit_t *) kryptos_newseg(kryptos_mp_byte2bit(src->data_size));
    }

    memset((*dest)->data, 0, (*dest)->data_size * sizeof(kryptos_mp_digit_t));

    d = src->data_size - 1;

    while (d >= 0) {
        (*dest)->data[d] = src->data[d];
        d--;
    }

    return *dest;
}

kryptos_mp_value_t *kryptos_hex_value_as_mp(const char *value, const size_t value_size) {
    kryptos_mp_value_t *mp;
    const char *vp, *vp_end;
    ssize_t d;
    kryptos_u8_t nb;
#ifdef KRYPTOS_MP_U32_DIGIT
    size_t w, v;
    char *padded_value = NULL;
#endif

    if (value == NULL || value_size == 0) {
        return NULL;
    }

#ifndef KRYPTOS_MP_U32_DIGIT

    mp = kryptos_new_mp_value(value_size << 2);

#else

    v = value_size;

    while ((v % 8) != 0) {
        v++;
    }

    mp = kryptos_new_mp_value(v << 2);

#endif

    if (mp == NULL) {
        return NULL;
    }

    vp = value;
    vp_end = vp + value_size;

    d = mp->data_size - 1;

#ifndef KRYPTOS_MP_U32_DIGIT

    if ((value_size % 2) != 0) {
        mp->data[d] = kryptos_mp_xnb(*vp);
        d--;
        vp++;
    }

    while (vp < vp_end && d >= 0) {
        nb = 0;
        if ((vp + 1) != vp_end) {
            nb = kryptos_mp_xnb(*(vp + 1));
        }

        mp->data[d] = (kryptos_mp_xnb(*vp) << 4) | nb;

        vp += 2;

        d--;
    }

#else
    w = 0;

    if (v != value_size) {
        padded_value = (char *) kryptos_newseg(v + 1);
        memset(padded_value, 0, v + 1);
        memset(padded_value, '0', v);
        memcpy(padded_value + (v - value_size), value, value_size);
        vp = padded_value;
        vp_end = vp + v;
    }

    while (vp < vp_end && d >= 0) {
        nb = kryptos_mp_xnb(*(vp));

        mp->data[d] <<= 4;

        if ((vp + 1) != vp_end) {
            nb = (nb << 4) | kryptos_mp_xnb(*(vp + 1));
            mp->data[d] <<= 4;
        }

        mp->data[d] |= nb;

        w = (w + 1) % sizeof(kryptos_mp_digit_t);

        if (w == 0) {
            d--;
        }

        vp += 2;
    }

    if (padded_value != NULL) {
        kryptos_freeseg(padded_value);
    }
#endif

    return mp;
}

kryptos_u8_t *kryptos_mp_value_as_hex(const kryptos_mp_value_t *value, size_t *hex_size) {
    ssize_t d;
    kryptos_u8_t *hex, *hp, *hp_end;

    if (value == NULL || hex_size == NULL) {
        return NULL;
    }

#ifndef KRYPTOS_MP_U32_DIGIT
    *hex_size = value->data_size << 1;
#else
    *hex_size = (value->data_size << 2) << 1;
#endif

    hex = (kryptos_u8_t *) kryptos_newseg(*hex_size + 1);

    if (hex == NULL) {
        *hex_size = 0;
        return NULL;
    }

    memset(hex, 0, *hex_size + 1);

    d = value->data_size - 1;

    hp = hex;
    hp_end = hp + *hex_size;

#ifndef KRYPTOS_MP_U32_DIGIT

    while (d >= 0) {
        *hp       = kryptos_mp_nbx(value->data[d] >> 4);
        *(hp + 1) = kryptos_mp_nbx(value->data[d] & 0xF);
        hp += 2;
        d--;
    }

#else
    while (d >= 0) {
        *hp       = kryptos_mp_nbx(value->data[d] >> 28);
        *(hp + 1) = kryptos_mp_nbx((value->data[d] >> 24) & 0xF);
        *(hp + 2) = kryptos_mp_nbx((value->data[d] >> 20) & 0xF);
        *(hp + 3) = kryptos_mp_nbx((value->data[d] >> 16) & 0xF);
        *(hp + 4) = kryptos_mp_nbx((value->data[d] >> 12) & 0xF);
        *(hp + 5) = kryptos_mp_nbx((value->data[d] >>  8) & 0xF);
        *(hp + 6) = kryptos_mp_nbx((value->data[d] >>  4) & 0xF);
        *(hp + 7) = kryptos_mp_nbx(value->data[d] & 0xF);
        hp += 8;
        d--;
    }
#endif

    return hex;
}

#ifndef KRYPTOS_MP_U32_DIGIT

static kryptos_mp_value_t *kryptos_mp_pad_for_multibyte(const kryptos_mp_value_t *v) {
    ssize_t s = v->data_size;
    kryptos_mp_value_t *p = NULL;

    while ((s % 4) != 0) {
        s++;
    }

    p = kryptos_new_mp_value(s << 3);
    p = kryptos_assign_mp_value(&p, v);

    return p;
}

static kryptos_mp_value_t *kryptos_mp_multibyte_add(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b) {
    // FACTS(Rafael):   1. a and b are non-null values.
    //                  2. a is always longer than b.
    //
    //                  otherwise you have introduced a bug.
    kryptos_mp_value_t *a4 = NULL, *b4 = NULL, *sum = NULL;
    kryptos_u64_t u64sum;
    kryptos_u8_t c;
    ssize_t i, s;

    if ((a4 = kryptos_mp_pad_for_multibyte(a)) == NULL) {
        goto kryptos_mp_multibyte_add_epilogue;
    }

    if ((b4 = kryptos_mp_pad_for_multibyte(b)) == NULL) {
        goto kryptos_mp_multibyte_add_epilogue;
    }

    sum = kryptos_new_mp_value((a4->data_size + b4->data_size) << 3);

    if (sum == NULL) {
        goto kryptos_mp_multibyte_add_epilogue;
    }

    s = i = 0;
    c = 0;

    while (i < a4->data_size) {
        u64sum = (kryptos_u64_t) kryptos_mp_get_u32_from_mp(a4, i) + (kryptos_u64_t) kryptos_mp_get_u32_from_mp(b4, i) + c;
        c = (u64sum > 0xFFFFFFFF);
        kryptos_mp_put_u32_into_mp(sum, s, u64sum);
        i += 4;
        s += 4;
    }

    if (c > 0 && s < sum->data_size) {
        sum->data[s] = c;
    }

kryptos_mp_multibyte_add_epilogue:

    if (a4 != NULL) {
        kryptos_del_mp_value(a4);
    }

    if (b4 != NULL) {
        kryptos_del_mp_value(b4);
    }

    return sum;
}

#endif

kryptos_mp_value_t *kryptos_mp_add(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src) {
    ssize_t d, s, sn;
#ifndef KRYPTOS_MP_U32_DIGIT
    kryptos_u16_t bsum;
#else
    kryptos_u64_t bsum;
#endif
    kryptos_u8_t c;
    kryptos_mp_value_t *sum;
    const kryptos_mp_value_t *a, *b;

    if (dest == NULL || src == NULL) {
        return NULL;
    }

    if ((*dest) == NULL) {
        (*dest) = kryptos_new_mp_value(src->data_size << 3);
        memcpy((*dest)->data, src->data, src->data_size);
        return (*dest);
    }

    kryptos_mp_max_min(a, b, (*dest), src);

#ifndef KRYPTOS_MP_U32_DIGIT

    if (a->data_size >= KRYPTOS_MP_MULTIBYTE_FLOOR) {
        // INFO(Rafael): We can process the data bytes as 32-bit groups. So, for example, if we have 128 bytes to sum
        //               96 iterations will be avoided.
        if ((sum = kryptos_mp_multibyte_add(a, b)) != NULL) {
            goto kryptos_mp_add_epilogue;
        }
    }

    sum = kryptos_new_mp_value(kryptos_mp_byte2bit(a->data_size));

#else

    sum = kryptos_new_mp_value(kryptos_mp_byte2bit((src->data_size + (*dest)->data_size)));

#endif

    if (sum == NULL) {
        return NULL;
    }

    d = s = 0;
    c = 0;

    while (d < a->data_size) {
#ifndef KRYPTOS_MP_U32_DIGIT
        bsum = a->data[d] + ( (d < b->data_size) ? b->data[d] : 0 ) + c;
        c = (bsum > 0xFF);
        sum->data[s] = bsum & 0xFF;
#else
        bsum = (kryptos_u64_t)a->data[d] + (kryptos_u64_t)((d < b->data_size) ? b->data[d] : 0) + c;
        c = (bsum > 0xFFFFFFFF);
        sum->data[s] = bsum & 0xFFFFFFFF;
#endif
        s++;
        d++;
    }

    if (c > 0 && s < sum->data_size) {
        sum->data[s] = c;
    }

#ifndef KRYPTOS_MP_U32_DIGIT
kryptos_mp_add_epilogue:
#endif

    for (sn = sum->data_size - 1; sn >= 0 && sum->data[sn] == 0; sn--)
        ;

    (*dest)->data_size = (sn < sum->data_size) ? sn + 1 : sum->data_size;
    kryptos_freeseg((*dest)->data);

    (*dest)->data = (kryptos_mp_digit_t *) kryptos_newseg((*dest)->data_size * sizeof(kryptos_mp_digit_t));

    if ((*dest)->data != NULL) {
        for (s = sn; s >= 0; s--) {
            (*dest)->data[s] = sum->data[s];
        }
    } else {
        (*dest)->data = sum->data;
        sum->data = NULL;
    }

    kryptos_del_mp_value(sum);

    return (*dest);
}

ssize_t kryptos_mp_bitcount(const kryptos_mp_value_t *n) {
    ssize_t b, dn;

    if (n == NULL) {
        return 0;
    }

    dn = n->data_size - 1;

    b = dn << 3;

#ifndef KRYPTOS_MP_U32_DIGIT
    if (n->data[dn] >> 7) {
        b += 8;
    } else if (n->data[dn] >> 6) {
        b += 7;
    } else if (n->data[dn] >> 5) {
        b += 6;
    } else if (n->data[dn] >> 4) {
        b += 5;
    } else if (n->data[dn] >> 3) {
        b += 4;
    } else if (n->data[dn] >> 2) {
        b += 3;
    } else if (n->data[dn] >> 1) {
        b += 2;
    } else if (n->data[dn] & 0x1) {
        b += 1;
    }
#else
    if (n->data[dn] >> 31) {
        b += 32;
    } else if (n->data[dn] >> 30) {
        b += 31;
    } else if (n->data[dn] >> 29) {
        b += 30;
    } else if (n->data[dn] >> 28) {
        b += 29;
    } else if (n->data[dn] >> 27) {
        b += 28;
    } else if (n->data[dn] >> 26) {
        b += 27;
    } else if (n->data[dn] >> 25) {
        b += 26;
    } else if (n->data[dn] >> 24) {
        b += 25;
    } else if (n->data[dn] >> 23) {
        b += 24;
    } else if (n->data[dn] >> 22) {
        b += 23;
    } else if (n->data[dn] >> 21) {
        b += 22;
    } else if (n->data[dn] >> 20) {
        b += 21;
    } else if (n->data[dn] >> 19) {
        b += 20;
    } else if (n->data[dn] >> 18) {
        b += 19;
    } else if (n->data[dn] >> 17) {
        b += 18;
    } else if (n->data[dn] >> 16) {
        b += 17;
    } else if (n->data[dn] >> 15) {
        b += 16;
    } else if (n->data[dn] >> 14) {
        b += 15;
    } else if (n->data[dn] >> 13) {
        b += 14;
    } else if (n->data[dn] >> 12) {
        b += 13;
    } else if (n->data[dn] >> 11) {
        b += 12;
    } else if (n->data[dn] >> 10) {
        b += 11;
    } else if (n->data[dn] >>  9) {
        b += 10;
    } else if (n->data[dn] >>  8) {
        b += 9;
    } else if (n->data[dn] >>  7) {
        b += 8;
    } else if (n->data[dn] >>  6) {
        b += 7;
    } else if (n->data[dn] >>  5) {
        b += 6;
    } else if (n->data[dn] >>  4) {
        b += 5;
    } else if (n->data[dn] >>  3) {
        b += 4;
    } else if (n->data[dn] >>  2) {
        b += 3;
    } else if (n->data[dn] >>  1) {
        b += 2;
    } else if (n->data[dn] & 0x1) {
        b += 1;
    }
#endif

    return b;
}

/*static kryptos_mp_value_t *kryptos_mp_multibyte_sub(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b) {
    kryptos_mp_value_t *a4 = NULL, *b4 = NULL, *delta = NULL;
    kryptos_u64_t u64sub;
    kryptos_u64_t c;
    ssize_t s, dn, d, bn;

    if ((a4 = kryptos_mp_pad_for_multibyte(a)) == NULL) {
        goto kryptos_mp_multibyte_sub_epilogue;
    }

    if ((b4 = kryptos_mp_pad_for_multibyte(b)) == NULL) {
        goto kryptos_mp_multibyte_sub_epilogue;
    }

    dn = (a4->data_size > b4->data_size) ? a4->data_size : b4->data_size;

    //delta = kryptos_new_mp_value((a4->data_size + b4->data_size) << 3);
    delta = kryptos_new_mp_value(dn << 3);

    if (delta == NULL) {
        goto kryptos_mp_multibyte_sub_epilogue;
    }

    s = d = 0;
    c = 0;

    if (a->data_size > b->data_size) {
        bn = a->data_size;
    } else {
        bn = b->data_size;
    }

    while (d < dn) {
        u64sub = (kryptos_u64_t) kryptos_mp_get_u32_from_mp(a4, d) - (kryptos_u64_t) kryptos_mp_get_u32_from_mp(b4, d) + c;
        c += u64sub >> 32;
        kryptos_mp_put_u32_into_mp(delta, s, u64sub);
        d += 4;
        s += 4;
    }

    if (c == 0xFFFFFFFF && s < delta->data_size) {
        delta->data[s] = 0x0F;
    }

    if (dn != bn) {
        d = delta->data_size - 1;
        delta->data[d] &= 1 << (dn - bn);
    }

    kryptos_print_mp(delta);
    printf("bn = %d | %d\n", bn, dn);

kryptos_mp_multibyte_sub_epilogue:

    if (a4 != NULL) {
        kryptos_del_mp_value(a4);
    }

    if (b4 != NULL) {
        kryptos_del_mp_value(b4);
    }

    return delta;
}*/

kryptos_mp_value_t *kryptos_mp_sub(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src) {
    ssize_t d, s, sn, dn;
#ifndef KRYPTOS_MP_U32_DIGIT
    kryptos_u16_t bsub;
    kryptos_u8_t c;
#else
    kryptos_u64_t bsub;
    kryptos_u32_t c;
#endif
    kryptos_mp_value_t *delta;
    int is_zero = 0;

    if (dest == NULL || src == NULL) {
        return NULL;
    }

    if ((*dest) == NULL) {
        (*dest) = kryptos_new_mp_value(kryptos_mp_byte2bit(src->data_size));
        memcpy((*dest)->data, src->data, src->data_size * sizeof(kryptos_mp_digit_t));
        return (*dest);
    }

    // INFO(Rafael): Checking for src == 0 or dest == 0.

    is_zero = 1;
    for (d = 0; d < src->data_size && is_zero; d++) {
        is_zero = (src->data[d] == 0);
    }

    if (is_zero) {
        return (*dest);
    }

    is_zero = 1;
    for (d = 0; d < (*dest)->data_size && is_zero; d++) {
        is_zero = ((*dest)->data[d] == 0);
    }

    if (is_zero) {
        kryptos_del_mp_value(*dest);
        *dest = NULL;
        return kryptos_assign_mp_value(dest, src);
    }

    dn = ((*dest)->data_size > src->data_size) ? (*dest)->data_size : src->data_size;

    // INFO(Rafael): Since we are subtracting there is no necessity of increasing the resultant delta.
    delta = kryptos_new_mp_value(kryptos_mp_byte2bit(dn));

    if (delta == NULL) {
        return NULL;
    }

    d = s = 0;
    c = 0;

    while (d < dn) {
#ifndef KRYPTOS_MP_U32_DIGIT
        bsub = ( (d < (*dest)->data_size) ? (*dest)->data[d] : 0 ) - ( (d < src->data_size) ? src->data[d] : 0 ) + c;
        c += bsub >> 8;
        delta->data[s] = bsub & 0xFF;
#else
        bsub = ( (d < (*dest)->data_size) ? (kryptos_u64_t)(*dest)->data[d] : 0 ) -
                ( (d < src->data_size) ? (kryptos_u64_t)src->data[d] : 0 ) + (kryptos_u64_t)c;
        c += bsub >> 32;
        delta->data[s] = bsub & 0xFFFFFFFF;
#endif
        s++;
        d++;
    }

#ifndef KRYPTOS_MP_U32_DIGIT
    if (c == 0xFF && s < delta->data_size) {
        // INFO(Rafael): Here in this code I am not really concerned about signals, the numbers are expressed with 2^b bits.
        //               However, we will sign that the src was greater than dest by setting the most significant nibble to 0xF.
        delta->data[s] = 0xFF;
    }
#else
    if (c == 0xFFFFFFFF && s < delta->data_size) {
        delta->data[s] = 0xFFFFFFFF;
    }
/*
    if (delta->data_size > 1 && delta->data[delta->data_size - 1] == 0x1) {
        // INFO(Rafael): Avoiding the unwanted carry "propagation".
        delta->data[delta->data_size - 1] = 0;
    }
*/
#endif

//kryptos_mp_sub_epilogue:

    for (sn = delta->data_size - 1; sn >= 0 && delta->data[sn] == 0; sn--)
        ;

    (*dest)->data_size = (sn < delta->data_size) ? sn + 1 : delta->data_size;
    kryptos_freeseg((*dest)->data);

    (*dest)->data = (kryptos_mp_digit_t *) kryptos_newseg((*dest)->data_size * sizeof(kryptos_mp_digit_t));
    memset((*dest)->data, 0, (*dest)->data_size * sizeof(kryptos_mp_digit_t));
    if ((*dest)->data != NULL) {
        for (s = sn; s >= 0; s--) {
            (*dest)->data[s] = delta->data[s];
        }
    } else {
        (*dest)->data = delta->data;
        delta->data = NULL;
    }

    kryptos_del_mp_value(delta);

    return (*dest);
}

kryptos_mp_value_t *kryptos_assign_hex_value_to_mp(kryptos_mp_value_t **dest,
                                                   const char *value, const size_t value_size) {
    const char *vp, *vp_end;
    ssize_t d;
    kryptos_u8_t nb;
#ifdef KRYPTOS_MP_U32_DIGIT
    size_t w;
#endif

    if (dest == NULL || value == NULL || value_size == 0) {
        return NULL;
    }

    if ((*dest) == NULL) {
        (*dest) = kryptos_hex_value_as_mp(value, value_size);
        return (*dest);
    }

    vp = value;
    vp_end = vp + value_size;

    memset((*dest)->data, 0, (*dest)->data_size);

    if ((value_size >> 1) > (*dest)->data_size) {
        d = (*dest)->data_size - 1;
    } else {
        d = (value_size >> 1) - 1;
    }

#ifndef KRYPTOS_MP_U32_DIGIT
    while (vp < vp_end && d >= 0) {
        nb = 0;

        if ((vp + 1) != vp_end) {
            nb = kryptos_mp_xnb(*(vp + 1));
        }

        (*dest)->data[d] = (kryptos_mp_xnb(*vp) << 4) | nb;

        vp += 2;
        d--;
    }
#else
    w = 0;

    while (vp < vp_end && d >= 0) {
        nb = 0;

        if ((vp + 1) != vp_end) {
            nb = kryptos_mp_xnb(*(vp + 1));
        }

        (*dest)->data[d] = (*dest)->data[d] << 8 | ((kryptos_mp_xnb(*vp) << 4) | nb);

        w = (w + 1) % sizeof(kryptos_mp_digit_t);

        if (w == 0) {
            d--;
        }

        vp += 2;
    }

#endif

    return (*dest);
}

#ifndef KRYPTOS_MP_U32_DIGIT

static kryptos_mp_value_t *kryptos_mp_multibyte_mul(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b) {
    kryptos_mp_value_t *a4 = NULL, *b4 = NULL, *mul = NULL;
    kryptos_u64_t u64mul, u64sum;
    kryptos_u8_t ac;
    ssize_t ad, bd, r;
    kryptos_u32_t mc;

    if ((a4 = kryptos_mp_pad_for_multibyte(a)) == NULL) {
        goto kryptos_mp_multibyte_mul_epilogue;
    }

    if ((b4 = kryptos_mp_pad_for_multibyte(b)) == NULL) {
        goto kryptos_mp_multibyte_mul_epilogue;
    }

    mul = kryptos_new_mp_value((a4->data_size + b4->data_size + 4) << 3);

    if (mul == NULL) {
        goto kryptos_mp_multibyte_mul_epilogue;
    }

    for (bd = 0, r = 0; bd < b4->data_size; bd += 4, r += 4) {
        mc = 0;
        ac = 0;

        for (ad = 0; ad < a4->data_size; ad += 4) {
            u64mul = (kryptos_u64_t) kryptos_mp_get_u32_from_mp(b4, bd) *
                        (kryptos_u64_t) kryptos_mp_get_u32_from_mp(a4, ad) + (kryptos_u64_t) mc;
            mc = u64mul >> 32;

            u64sum = (kryptos_u64_t) kryptos_mp_get_u32_from_mp(mul, ad + r) + (u64mul & 0xFFFFFFFF) + (kryptos_u64_t) ac;
            ac = (u64sum > 0xFFFFFFFF);
            kryptos_mp_put_u32_into_mp(mul, ad + r, u64sum);
        }

        if ((ad + r) < mul->data_size) {
            u64sum = ((kryptos_u64_t) kryptos_mp_get_u32_from_mp(mul, ad + r) + mc + ac) & 0xFFFFFFFF;
            kryptos_mp_put_u32_into_mp(mul, ad + r, u64sum);
        }
    }

kryptos_mp_multibyte_mul_epilogue:

    if (a4 != NULL) {
        kryptos_del_mp_value(a4);
    }

    if (b4 != NULL) {
        kryptos_del_mp_value(b4);
    }

    return mul;
}

#endif

kryptos_mp_value_t *kryptos_mp_mul(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src) {
    size_t r;
    kryptos_mp_value_t *m;
    const kryptos_mp_value_t *x, *y;
    ssize_t xd, yd;
#ifndef KRYPTOS_MP_U32_DIGIT
    short bmul;
    kryptos_u16_t bsum;
    kryptos_u8_t mc, ac;
#else
    long long bmul;
    kryptos_u64_t bsum;
    kryptos_u32_t mc;
    kryptos_u8_t ac;
#endif

    if (src == NULL || dest == NULL) {
        return NULL;
    }

    if ((*dest) == NULL) {
        (*dest) = kryptos_new_mp_value(src->data_size << 3);
        memcpy((*dest)->data, src->data, src->data_size);
        return (*dest);
    }

    kryptos_mp_max_min(x, y, (*dest), src);

#ifndef KRYPTOS_MP_U32_DIGIT
    if (x->data_size >= KRYPTOS_MP_MULTIBYTE_FLOOR) {
        if ((m = kryptos_mp_multibyte_mul(x, y)) != NULL) {
            goto kryptos_mp_mul_epilogue;
        }
    }
#endif

    // CLUE(Rafael): Encantamentos baseados em algumas propriedades que talvez a tia Tetéia não quis te contar.

    m = kryptos_new_mp_value(kryptos_mp_byte2bit((*dest)->data_size + src->data_size + 1));

    if (m == NULL) {
        // WARN(Rafael): Better let a memory leak than return a wrong result.
        return NULL;
    }

    // CLUE(Rafael): Multiplicando igual na aula da tia Tetéia.

    for (yd = 0, r = 0; yd < y->data_size; yd++, r++) {
        mc = 0;
        ac = 0;
#ifndef KRYPTOS_MP_U32_DIGIT
        for (xd = 0; xd < x->data_size; xd++) {
            bmul = y->data[yd] * x->data[xd] + mc;
            mc = (bmul >> 8);
            // INFO(Rafael): "Parallelizing" the multiplications sum in order to not call kryptos_mp_add() x->data_size times.
            //               Besides time it will also save memory.
            bsum = m->data[xd + r] + (bmul & 0xFF) + ac;
            ac = (bsum > 0xFF);
            m->data[xd + r] = (bsum & 0xFF);
        }

        if ((xd + r) < m->data_size) {
            m->data[xd + r] = (m->data[xd + r] + mc + ac) & 0xFF;
        }
#else
        for (xd = 0; xd < x->data_size; xd++) {
            bmul = (kryptos_u64_t)y->data[yd] * (kryptos_u64_t)x->data[xd] + (kryptos_u64_t)mc;
            mc = (bmul >> 32);
            bsum = m->data[xd + r] + (bmul & 0xFFFFFFFF) + ac;
            ac = (bsum > 0xFFFFFFFF);
            m->data[xd + r] = (bsum & 0xFFFFFFFF);
        }

        if ((xd + r) < m->data_size) {
            m->data[xd + r] = (m->data[xd + r] + mc + ac) & 0xFFFFFFFF;
        }
#endif
    }

#ifndef KRYPTOS_MP_U32_DIGIT
kryptos_mp_mul_epilogue:
#endif

    for (xd = m->data_size - 1; xd >= 0 && m->data[xd] == 0; xd--)
        ;

    kryptos_del_mp_value((*dest));
    (*dest) = NULL;

    (*dest) = kryptos_new_mp_value(kryptos_mp_byte2bit(xd + 1));

    for (yd = xd; yd >= 0; yd--) {
        (*dest)->data[yd] = m->data[yd];
    }

    // INFO(Rafael): Housekeeping.
    kryptos_del_mp_value(m);
    r = 0;
    bmul = 0;
    ac = mc = 0;
    bmul = 0;
    bsum = 0;

    return (*dest);
}

int kryptos_mp_eq(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b) {
    size_t d;
    const kryptos_mp_value_t *aa, *bb;

    if (a == NULL || b == NULL) {
        return 0;
    }

    if (a->data_size == b->data_size) {
        return (memcmp(a->data, b->data, a->data_size * sizeof(kryptos_mp_digit_t)) == 0);
    }

    kryptos_mp_max_min(aa, bb, a, b);

    if (aa->data_size != bb->data_size) {
        for (d = bb->data_size; d < aa->data_size; d++) {
            if (aa->data[d] != 0) {
                return 0;
            }
        }
    }

    for (d = 0; d < bb->data_size; d++) {
        if (aa->data[d] != bb->data[d]) {
            return 0;
        }
    }

    return 1;
}

const kryptos_mp_value_t *kryptos_mp_get_gt(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b) {
    ssize_t d;
    const kryptos_mp_value_t *aa, *bb;
    kryptos_u8_t x, y;

    if (a == NULL || b == NULL) {
        return NULL;
    }

    kryptos_mp_max_min(aa, bb, a, b);

    if (aa->data_size != bb->data_size) {
        for (d = bb->data_size; d < aa->data_size; d++) {
            if (aa->data[d] != 0) {
                return aa;
            }
        }
    }

#define kryptos_mp_get_gt_bitcmp(aa, bb, n, b, ax, bx) {\
    (ax) = ((aa)->data[n] & (1 << (b))) >> (b);\
    (bx) = ((bb)->data[n] & (1 << (b))) >> (b);\
    if ((ax) && !(bx)) {\
        return (aa);\
    }\
    if ((bx) && !(ax)) {\
        return (bb);\
    }\
}

#ifndef KRYPTOS_MP_U32_DIGIT

    for (d = bb->data_size - 1; d >= 0; d--) {
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 7, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 6, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 5, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 4, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 3, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 2, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 1, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 0, x, y);
    }

#else

    for (d = bb->data_size - 1; d >= 0; d--) {
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 31, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 30, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 29, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 28, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 27, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 26, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 25, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 24, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 23, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 22, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 21, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 20, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 19, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 18, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 17, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 16, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 15, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 14, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 13, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 12, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 11, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d, 10, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d,  9, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d,  8, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d,  7, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d,  6, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d,  5, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d,  4, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d,  3, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d,  2, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d,  1, x, y);
        kryptos_mp_get_gt_bitcmp(aa, bb, d,  0, x, y);
    }

#endif

#undef kryptos_mp_get_gt_bitcmp

    return NULL;
}

kryptos_mp_value_t *kryptos_mp_pow(const kryptos_mp_value_t *g, const kryptos_mp_value_t *e) {
    kryptos_mp_value_t *A = NULL;
    ssize_t t;

    if (g == NULL || e == NULL) {
        return NULL;
    }

    A = kryptos_hex_value_as_mp("1", 1);

#define kryptos_mp_pow_step(e, t, bn, A, g) {\
    A = kryptos_mp_mul(&A, A);\
    if ( ( ((e)->data[t] & (1 << (bn))) >> (bn) ) ) {\
        A = kryptos_mp_mul(&A, g);\
    }\
}

    for (t = e->data_size - 1; t >= 0; t--) {
#ifdef KRYPTOS_MP_U32_DIGIT
        kryptos_mp_pow_step(e, t, 31, A, g);
        kryptos_mp_pow_step(e, t, 30, A, g);
        kryptos_mp_pow_step(e, t, 29, A, g);
        kryptos_mp_pow_step(e, t, 28, A, g);
        kryptos_mp_pow_step(e, t, 27, A, g);
        kryptos_mp_pow_step(e, t, 26, A, g);
        kryptos_mp_pow_step(e, t, 25, A, g);
        kryptos_mp_pow_step(e, t, 24, A, g);
        kryptos_mp_pow_step(e, t, 23, A, g);
        kryptos_mp_pow_step(e, t, 22, A, g);
        kryptos_mp_pow_step(e, t, 21, A, g);
        kryptos_mp_pow_step(e, t, 20, A, g);
        kryptos_mp_pow_step(e, t, 19, A, g);
        kryptos_mp_pow_step(e, t, 18, A, g);
        kryptos_mp_pow_step(e, t, 17, A, g);
        kryptos_mp_pow_step(e, t, 16, A, g);
        kryptos_mp_pow_step(e, t, 15, A, g);
        kryptos_mp_pow_step(e, t, 14, A, g);
        kryptos_mp_pow_step(e, t, 13, A, g);
        kryptos_mp_pow_step(e, t, 12, A, g);
        kryptos_mp_pow_step(e, t, 11, A, g);
        kryptos_mp_pow_step(e, t, 10, A, g);
        kryptos_mp_pow_step(e, t,  9, A, g);
        kryptos_mp_pow_step(e, t,  8, A, g);
#endif
        kryptos_mp_pow_step(e, t, 7, A, g);
        kryptos_mp_pow_step(e, t, 6, A, g);
        kryptos_mp_pow_step(e, t, 5, A, g);
        kryptos_mp_pow_step(e, t, 4, A, g);
        kryptos_mp_pow_step(e, t, 3, A, g);
        kryptos_mp_pow_step(e, t, 2, A, g);
        kryptos_mp_pow_step(e, t, 1, A, g);
        kryptos_mp_pow_step(e, t, 0, A, g);
    }

#undef kryptos_mp_pow_step

    return A;
}

void kryptos_print_mp(const kryptos_mp_value_t *v) {
    if (v == NULL) {
        return;
    }
#if !defined(KRYPTOS_KERNEL_MODE)
    ssize_t d;
# ifndef KRYPTOS_MP_U32_DIGIT
    for (d = v->data_size - 1; d >= 0; d--) printf("%.2X", v->data[d]);
# else
    for (d = v->data_size - 1; d >= 0; d--) printf("%.8X", v->data[d]);
# endif
    printf("\n");
#else
# if defined(__FreeBSD__)
    ssize_t d;
#  ifndef KRYPTOS_MP_U32_DIGIT
    for (d = v->data_size - 1; d >= 0; d--) uprintf("%.2X", v->data[d]);
#  else
    for (d = v->data_size - 1; d >= 0; d--) uprintf("%.8X", v->data[d]);
#  endif
    uprintf("\n");
# elif defined(__linux__)
/*
#  ifndef KRYPTOS_MP_U32_DIGIT
    for (d = v->data_size - 1; d >= 0; d--) printk(KERN_ERR "%.2X", v->data[d]);
#  else
    for (d = v->data_size - 1; d >= 0; d--) printk(KERN_ERR "%.8X", v->data[d]);
#  endif
    printk(KERN_ERR "\n");
*/
# endif
#endif
}

/*static ssize_t kryptos_mp_max_used_byte(const kryptos_mp_value_t *x) {
    ssize_t b;
    for (b = x->data_size - 1; b >= 0 && x->data[b] == 0; b--)
        ;
    return b;
}*/

kryptos_mp_value_t *kryptos_mp_mul_digit(kryptos_mp_value_t **x, const kryptos_mp_digit_t digit) {
    ssize_t d;
#ifndef KRYPTOS_MP_U32_DIGIT
    kryptos_u8_t mc = 0;
    short bmul;
#else
    kryptos_u32_t mc = 0;
    long long bmul;
#endif

    if (x == NULL) {
        return NULL;
    }

    for (d = 0; d < (*x)->data_size; d++) {
#ifndef KRYPTOS_MP_U32_DIGIT
        bmul = (*x)->data[d] * digit + mc;
        mc = (bmul >> 8);
        (*x)->data[d] = (bmul & 0xFF);
#else
        bmul = (kryptos_u64_t)(*x)->data[d] * (kryptos_u64_t)digit + (kryptos_u64_t)mc;
        mc = (bmul >> 32);
        (*x)->data[d] = (bmul & 0xFFFFFFFF);
#endif
    }

    if (mc > 0) {
#ifndef KRYPTOS_MP_U32_DIGIT
        (*x) = kryptos_mp_lsh(x, 8);
        (*x) = kryptos_mp_rsh(x, 8);
#else
        (*x) = kryptos_mp_lsh(x, 32);
        (*x) = kryptos_mp_rsh(x, 32);
#endif
        (*x)->data[(*x)->data_size - 1] = mc;
    }

    return (*x);
}

#ifndef KRYPTOS_MP_SLOWER_MP_DIV

// WARN(Rafael): You should define KRYPTOS_MP_U32_DIGIT (btw, this is the default). The kryptos_mp_div_tests case
//               when using radix 2^32, in a SMP, takes ~0m0.265s against ~0m5.768s with radix 2^8.

#undef KRYPTOS_MP_DIV_DEBUG_INFO

#ifdef KRYPTOS_MP_U32_DIGIT
// WARN(Rafael): For radix 2^32 is better apply normalization, otherwise the things can slow down in some cases.
# define KRYPTOS_MP_DIV_APPLY_NORMALIZATION 1
#else
// WARN(Rafael): The normalization for 2^8 does not seem to worth.
# undef KRYPTOS_MP_DIV_APPLY_NORMALIZATION
#endif

kryptos_mp_value_t *kryptos_mp_div(const kryptos_mp_value_t *x, const kryptos_mp_value_t *y, kryptos_mp_value_t **r) {
    kryptos_mp_value_t *q = NULL, *xn = NULL, *yn = NULL, *b = NULL;
    kryptos_mp_value_t *t = NULL;
    ssize_t d, dn;
    ssize_t n, m, j, xi;
#ifndef KRYPTOS_MP_U32_DIGIT
    kryptos_u16_t qtemp;
#else
    kryptos_u64_t qtemp;
    int dec_nr;
#endif
    int is_zero = 0, is_less;
#ifdef KRYPTOS_MP_DIV_APPLY_NORMALIZATION
    int shlv_nm = 0;
#endif

    if (x == NULL || y == NULL) {  // INFO(Rafael): One or both div op variables passed as null.
        if (r != NULL) {
            (*r) = NULL;  // INFO(Rafael): Who knows.... who knows...
        }
        return NULL;
    }

    is_zero = 1;
    for (d = y->data_size - 1; d >= 0 && is_zero; d--) {
        is_zero = (y->data[d] == 0x00);
    }

    if (is_zero) {  // INFO(Rafael): Division by zero.
        if (r != NULL) {
            (*r) = NULL;
        }
        return NULL;
    }

    is_zero = 1;
    for (d = x->data_size - 1; d >= 0 && is_zero; d--) {
        is_zero = (x->data[d] == 0x00);
    }

    if (is_zero) {  // INFO(Rafael): 0 divided by y.
        if (r != NULL) {
            (*r) = kryptos_hex_value_as_mp("0", 1);
        }
        return kryptos_hex_value_as_mp("0", 1);
    }

    if (kryptos_mp_lt(x, y)) {  // INFO(Rafael): x < y.
        if (r != NULL) {
            (*r) = NULL;
            (*r) = kryptos_assign_mp_value(r, x);
        }
        return kryptos_hex_value_as_mp("0", 1);
    }

    m = kryptos_mp_byte2bit(x->data_size);

#ifndef KRYPTOS_MP_U32_DIGIT
    while (m % 64) {
        m++;
    }
#endif

    if ((xn = kryptos_new_mp_value(m)) == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    if ((xn = kryptos_assign_mp_value(&xn, x)) == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    if ((yn = kryptos_assign_mp_value(&yn, y)) == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    n = yn->data_size;

    while (yn->data[n - 1] == 0 && n >= 1) {
        n--;
    }

    // INFO(Rafael): Normalizing.

#ifdef KRYPTOS_MP_DIV_APPLY_NORMALIZATION
# ifndef KRYPTOS_MP_U32_DIGIT
    if (yn->data[n - 1] < 0x80) {
        if ((yn->data[n - 1] & 0x01) == 0x01) {
            shlv_nm = 7;
        } else if ((yn->data[n - 1] & 0x02) == 0x02) {
            shlv_nm = 6;
        } else if ((yn->data[n - 1] & 0x04) == 0x04) {
            shlv_nm = 5;
        } else if ((yn->data[n - 1] & 0x08) == 0x08) {
            shlv_nm = 4;
        } else if ((yn->data[n - 1] & 0x10) == 0x10) {
            shlv_nm = 3;
        } else if ((yn->data[n - 1] & 0x20) == 0x20) {
            shlv_nm = 2;
        } else if ((yn->data[n - 1] & 0x40) == 0x40) {
            shlv_nm = 1;
        }

        xn = kryptos_mp_lsh(&xn, shlv_nm);
        yn = kryptos_mp_lsh(&yn, shlv_nm);

        n = yn->data_size;
        while (yn->data[n - 1] == 0 && n >= 1) {
            n--;
        }
    }
# else
    while (yn->data[n - 1] < 0x80000000) {
        shlv_nm++;
        xn = kryptos_mp_lsh(&xn, 1);
        yn = kryptos_mp_lsh(&yn, 1);
        n = yn->data_size;
        while (yn->data[n - 1] == 0 && n >= 1) {
            n--;
        }
    }
# endif
#endif

    m = xn->data_size - yn->data_size;
    if (m <= 0) {
        m = 1;
    }

    if ((q = kryptos_new_mp_value(kryptos_mp_byte2bit(m + 1))) == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    if ((b = kryptos_assign_mp_value(&b, yn)) == NULL) {
        goto kryptos_mp_div_epilogue;
    }

#ifndef KRYPTOS_MP_U32_DIGIT
    b = kryptos_mp_lsh(&b, 8 * m);
    while (kryptos_mp_ge(xn, b)) {
        q->data[m]++;
        xn = kryptos_mp_sub(&xn, b);
    }
#else
    b = kryptos_mp_lsh(&b, 32 * m);
    if (kryptos_mp_ge(xn, b)) {
        t = kryptos_assign_mp_value(&t, xn);
    }

# ifdef KRYPTOS_MP_DIV_APPLY_NORMALIZATION
    while (kryptos_mp_ge(xn, b) && q->data[m] < 0xFF) {
        q->data[m]++;
        xn = kryptos_mp_sub(&xn, b);
    }

    // INFO(Rafael): This dirty trick (a.k.a. [in academic slang] heuristic) will try hit the right guessing by adding,
    //               however, only until 255 (the above loop). If 255 was hit without finding the right guessing,
    //               the algorithm will try to divide the two most significant digits and correct it from that (if necessary).
    if (q->data[m] == 0xFF && kryptos_mp_ge(xn, b)) {
        q->data[m] = 0;
        kryptos_del_mp_value(xn);
        xn = t;
        t = NULL;
        m++;
    } else if (t != NULL) {
        kryptos_del_mp_value(t);
        t = NULL;
    }
# else
    while (kryptos_mp_ge(xn, b)) { // WARN(Rafael): This is slower!
        q->data[m]++;
        xn = kryptos_mp_sub(&xn, b);
    }
# endif

#endif

    kryptos_del_mp_value(b);
    b = NULL;

    if (kryptos_mp_lt(xn, yn)) {
        goto kryptos_mp_div_epilogue;
    }

    for (j = m - 1; j >= 0; j--) {
        xi = n + j;

        while (xi >= xn->data_size) {
            xi--;
        }

        qtemp = xn->data[xi];

#ifndef KRYPTOS_MP_U32_DIGIT
        if ((xi - 1) >= 0) {
            xi--;
            qtemp = (qtemp << 8) | xn->data[xi];
        }
#else
        if ((xi - 1) >= 0) {
            xi--;
            qtemp = (qtemp << 32) | xn->data[xi];
        }
#endif

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
        printf("\tqtemp = %X\n", qtemp);
# ifndef KRYPTOS_MP_U32_DIGIT
        printf("\t%X / %X = ", qtemp, yn->data[n - 1]);
# else
        printf("\t%"PRIx64" / %X = ", qtemp, yn->data[n - 1]);
# endif
#endif

#ifndef KRYPTOS_MP_U32_DIGIT
        qtemp /= yn->data[n - 1];

        if (qtemp > 0xFF) {
            qtemp = 0xFF;
        }
#else

#if defined(__linux__) && defined(KRYPTOS_KERNEL_MODE)
        do_div(qtemp, (kryptos_u64_t) yn->data[n - 1]);
#else
        qtemp = qtemp / (kryptos_u64_t) yn->data[n - 1];
#endif

        if (qtemp > 0xFFFFFFFF) {
            qtemp = 0xFF;
        }

        dec_nr = 0;

#endif

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
        printf("%X\n", qtemp);
#endif

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
        printf("\t-- is_less loop begin.\n");
#endif

        do {

#ifndef KRYPTOS_MP_U32_DIGIT
            q->data[j] = qtemp & 0xFF;
#else
            q->data[j] = qtemp & 0xFFFFFFFF;
#endif
            b = kryptos_assign_mp_value(&b, yn);
            b = kryptos_mp_mul_digit(&b, q->data[j]);
#ifndef KRYPTOS_MP_U32_DIGIT
            b = kryptos_mp_lsh(&b, 8 * j);
#else
            b = kryptos_mp_lsh(&b, 32 * j);
#endif

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
            printf("\t\tis less??\n");
            printf("\t\txn = "); kryptos_print_mp(xn);
            printf("\t\tb  = "); kryptos_print_mp(b);
#endif

            is_less = kryptos_mp_lt(xn, b);

            if (is_less) {
#ifdef KRYPTOS_MP_U32_DIGIT
                dec_nr++;

                //  INFO(Rafael): dec_nr == 0xFF is another way of saying that the current fraction from "xn" cannot be
                //                divided by "yn" (Maybe 0xFF be overkill). In this case we need to "go down" one more
                //                digit, however, this long division is driven by computers not by humans, here
                //                "to go down" means "let's try to solve it in the next iterations when the shift
                //                level is less than the current one".
                if (dec_nr == 0xFF) {
                    q->data[j] = 0;
                    // WARN(Rafael): "break" and then call a "sub" with "b == 0"?? Are you programming for
                    //                the sake of the CPU or for the sake of newbie students? =D
                    goto kryptos_mp_div_end_of_iteration;
                }
#endif
                qtemp--;
                kryptos_del_mp_value(b);
                b = NULL;
#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
                printf("\t\tis_less == 1, qtemp = %X\n", qtemp);
#endif
            }
        } while (is_less);

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
        printf("\t-- is_less loop end.\n");
        printf("\txn' = "); kryptos_print_mp(xn);
        printf("\tb   = "); kryptos_print_mp(b);
#endif

        xn = kryptos_mp_sub(&xn, b);

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
        printf("\txn- = "); kryptos_print_mp(xn);
#endif

kryptos_mp_div_end_of_iteration:

        if (b != NULL) {
            kryptos_del_mp_value(b);
            b = NULL;
        }

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
        printf("-- end of iteration.\n");
        printf("\tQ'  = "); kryptos_print_mp(q);
        printf("\tXN' = "); kryptos_print_mp(xn);
        printf("--\n");
#endif

    }

kryptos_mp_div_epilogue:

#ifdef KRYPTOS_MP_DIV_APPLY_NORMALIZATION
    if (shlv_nm > 0) {
        xn = kryptos_mp_rsh(&xn, shlv_nm);
    }
#endif

    // INFO(Rafael): Eliminating unused bytes from remainder and quotient.

    if (r != NULL) {
        for (dn = xn->data_size - 1; dn >= 0 && xn->data[dn] == 0; dn--)
            ;

        if (((*r) = kryptos_new_mp_value(kryptos_mp_byte2bit(dn + 1))) != NULL) {
            for (d = 0; d <= dn; d++) {
                (*r)->data[d] = xn->data[d];
            }
         } else {
            (*r) = xn;
            xn = NULL;
         }
    }

    if (q != NULL) {
        for (dn = q->data_size - 1; dn >= 0 && q->data[dn] == 0; dn--)
            ;

        if (dn >= 0) {
            if ((b = kryptos_new_mp_value(kryptos_mp_byte2bit(dn + 1))) != NULL) {
                for (d = 0; d <= dn; d++) {
                    b->data[d] = q->data[d];
                }
                kryptos_del_mp_value(q);
                q = b;
            }
        }
    }

    if (xn != NULL) {
        kryptos_del_mp_value(xn);
    }

    if (yn != NULL) {
        kryptos_del_mp_value(yn);
    }

#ifdef KRYPTOS_MP_DIV_DEBUG_INFO
    printf("-- end of algorithm\n");
    printf("\tQ = "); kryptos_print_mp(q);
    printf("\tR = "); kryptos_print_mp(*r);
#endif

    return q;
}

#else

#ifndef KRYPTOS_MP_U32_DIGIT

kryptos_mp_value_t *kryptos_mp_div(const kryptos_mp_value_t *x, const kryptos_mp_value_t *y, kryptos_mp_value_t **r) {
    kryptos_mp_value_t *q = NULL;
    kryptos_mp_value_t *i = NULL;
    kryptos_mp_value_t *curr_x = NULL, *_1 = NULL, *sy = NULL;
    ssize_t d, di;
    int div_nr = 0, is_zero = 0;

    if (x == NULL || y == NULL) {  // INFO(Rafael): One or both div op variables passed as null.
        if (r != NULL) {
            (*r) = NULL;  // INFO(Rafael): Who knows.... who knows...
        }
        return NULL;
    }

    is_zero = 1;
    for (di = y->data_size - 1; di >= 0 && is_zero; di--) {
        is_zero = (y->data[di] == 0x00);
    }

    if (is_zero) {  // INFO(Rafael): Division by zero.
        if (r != NULL) {
            (*r) = NULL;
        }
        return NULL;
    }

    is_zero = 1;
    for (di = x->data_size - 1; di >= 0 && is_zero; di--) {
        is_zero = (x->data[di] == 0x00);
    }

    if (is_zero) {  // INFO(Rafael): 0 divided by y.
        if (r != NULL) {
            (*r) = kryptos_hex_value_as_mp("0", 1);
        }
        return kryptos_hex_value_as_mp("0", 1);
    }

    if (kryptos_mp_lt(x, y)) {  // INFO(Rafael): x < y.
        if (r != NULL) {
            (*r) = NULL;
            (*r) = kryptos_assign_mp_value(r, x);
        }
        return kryptos_hex_value_as_mp("0", 1);
    }

    q = kryptos_new_mp_value(x->data_size << 3);

    if (q == NULL) {
        goto kryptos_mp_div_epilogue;
    }

    curr_x = kryptos_new_mp_value(x->data_size << 3);
    if (curr_x == NULL) {
        kryptos_del_mp_value(q);
        q = NULL;
        goto kryptos_mp_div_epilogue;
    }

    _1 = kryptos_hex_value_as_mp("1", 1);
    if (_1 == NULL) {
        kryptos_del_mp_value(q);
        q = NULL;
        goto kryptos_mp_div_epilogue;
    }

    for (d = x->data_size - 1; d >= 0; d--) {
        curr_x->data[0] = x->data[d];
        if (kryptos_mp_ge(curr_x, y)) {
            do {
                div_nr = 1;
                if ((sy = kryptos_hex_value_as_mp("0", 1)) == NULL) {
                    kryptos_del_mp_value(q);
                    q = NULL;
                    goto kryptos_mp_div_epilogue;
                }
                if ((i = kryptos_hex_value_as_mp("0", 1)) == NULL) {
                    kryptos_del_mp_value(q);
                    q = NULL;
                    goto kryptos_mp_div_epilogue;
                }

                while (kryptos_mp_le(sy, curr_x)) {
                    sy = kryptos_mp_add(&sy, y);

                    if (sy == NULL) {
                        kryptos_del_mp_value(q);
                        q = NULL;
                        goto kryptos_mp_div_epilogue;
                    }

                    i = kryptos_mp_add(&i, _1);

                    if (i == NULL) {
                        kryptos_del_mp_value(q);
                        q = NULL;
                        goto kryptos_mp_div_epilogue;
                    }
                }

                i = kryptos_mp_sub(&i, _1);

                if (i == NULL) {
                    kryptos_del_mp_value(q);
                    q = NULL;
                    goto kryptos_mp_div_epilogue;
                }

                sy = kryptos_mp_sub(&sy, y);

                if (sy == NULL) {
                    kryptos_del_mp_value(q);
                    q = NULL;
                    goto kryptos_mp_div_epilogue;
                }

                curr_x = kryptos_mp_sub(&curr_x, sy);

                if (curr_x == NULL) {
                    kryptos_del_mp_value(q);
                    q = NULL;
                    goto kryptos_mp_div_epilogue;
                }

                for (di = i->data_size - 1; di >= 0; di--) {
                    q = kryptos_mp_lsh(&q, 8);
                    q->data[0] = i->data[di];
                }

                kryptos_del_mp_value(sy);
                kryptos_del_mp_value(i);
                sy = i = NULL;
            } while (kryptos_mp_ge(curr_x, y)); // INFO(Rafael): While is possible to divide... go into the loop again.
            curr_x = kryptos_mp_lsh(&curr_x, 8); // INFO(Rafael): Opens one position for the next digit.
            if (curr_x == NULL) {
                kryptos_del_mp_value(q);
                q = NULL;
                goto kryptos_mp_div_epilogue;
            }
        } else {
            curr_x = kryptos_mp_lsh(&curr_x, 8); // INFO(Rafael): Opens one position for the next digit.

            if (curr_x == NULL) {
                kryptos_del_mp_value(q);
                q = NULL;
                goto kryptos_mp_div_epilogue;
            }

            if (div_nr > 0) {
                q = kryptos_mp_lsh(&q, 8); // INFO(Rafael): The curr_x is not enough for dividing (curr_x < y).
                                           //               Thus, adds one digit zero to the quotient before getting
                                           //               the next digit from x.

                if (q == NULL) {
                    kryptos_del_mp_value(q);
                    q = NULL;
                    goto kryptos_mp_div_epilogue;
                }
            }
        }
    }

kryptos_mp_div_epilogue:
    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (r != NULL) {
        // INFO(Rafael): Reverting the remainder because there is nothing to get from x anymore.
        if (q != NULL) {
            curr_x = kryptos_mp_rsh(&curr_x, 8);
            (*r) = curr_x;
            curr_x = NULL;
        } else {
            (*r) = NULL;
        }
    }

    if (curr_x != NULL) {
        kryptos_del_mp_value(curr_x);
    }

    if (q != NULL) {  // INFO(Rafael): Eliminating unused bytes.
        for (di = q->data_size - 1; di >= 0 && q->data[di] == 0; di--)
            ;

        i = q;

        q = kryptos_new_mp_value((di + 1) << 3);

        for (d = 0; d <= di; d++) {
            q->data[d] = i->data[d];
        }

        kryptos_del_mp_value(i);
    }

    return q;
}

#endif

#endif

kryptos_mp_value_t *kryptos_mp_div_2p(const kryptos_mp_value_t *x, const kryptos_u32_t power, kryptos_mp_value_t **r) {
    kryptos_mp_value_t *q = NULL;
    kryptos_mp_value_t *p = NULL, *tr = NULL;
    ssize_t dn, d;

    if (x == NULL) {
        return NULL;
    }

    if ((q = kryptos_assign_mp_value(&q, x)) == NULL) {
        return NULL;
    }

    if ((q = kryptos_mp_rsh(&q, power)) == NULL) {
        return NULL;
    }

    if (r != NULL) {
        (*r) = NULL;
        if ((p = kryptos_new_mp_value(kryptos_mp_byte2bit(8))) == NULL) {
            goto kryptos_mp_div_2p_epilogue;
        }

        p->data[0] = 1;

        if ((p = kryptos_mp_lsh(&p, power)) == NULL) {
            goto kryptos_mp_div_2p_epilogue;
        }

        if ((p = kryptos_mp_mul(&p, q)) == NULL) {
            goto kryptos_mp_div_2p_epilogue;
        }

        if ((tr = kryptos_assign_mp_value(&tr, x)) == NULL) {
            goto kryptos_mp_div_2p_epilogue;
        }

        if ((tr = kryptos_mp_sub(&tr, p)) == NULL) {
            goto kryptos_mp_div_2p_epilogue;
        }

        for (dn = tr->data_size - 1; dn >= 0 && tr->data[dn] == 0; dn--)
            ;

        if (dn >= 0) {
            (*r) = kryptos_new_mp_value(kryptos_mp_byte2bit(dn + 1));
            if ((*r) != NULL) {
                for (d = 0; d <= dn; d++) {
                    (*r)->data[d] = tr->data[d];
                }
            }
        } else {
            (*r) = kryptos_new_mp_value(kryptos_mp_byte2bit(8));
        }

    }

kryptos_mp_div_2p_epilogue:

    if (tr != NULL) {
        kryptos_del_mp_value(tr);
    }

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    return q;
}

// WARN(Rafael): This is a good example of what is and what should be. People always tell us to use Montgomery,
//               however, it has been showing slower than MP division. So I have decided deactivate it.
//               Maybe this reduction worth in hardware or other more statical contexts.

#undef KRYPTOS_MP_ME_MOD_N_USE_MONTGOMERY_REDUCTION

kryptos_mp_value_t *kryptos_mp_me_mod_n(const kryptos_mp_value_t *m, const kryptos_mp_value_t *e, const kryptos_mp_value_t *n) {
    kryptos_mp_value_t *A = NULL, *mod = NULL, *div = NULL;
    ssize_t t;

    if (m == NULL || e == NULL || n == NULL) {
        return NULL;
    }

    if ((A = kryptos_hex_value_as_mp("1", 1)) == NULL) {
        return NULL;
    }

#ifdef KRYPTOS_MP_ME_MOD_N_USE_MONTGOMERY_REDUCTION

#define kryptos_mp_me_mod_n_mont(e, t, bn, A, m, n, mod) {\
    A = kryptos_mp_mul(&A, A);\
    mod = kryptos_mp_montgomery_reduction(A, n);\
    kryptos_del_mp_value(A);\
    A = mod;\
    mod = NULL;\
    if ( ( ((e)->data[t] & (1 << (bn))) >> (bn) ) ) {\
        A = kryptos_mp_mul(&A, m);\
        mod = kryptos_mp_montgomery_reduction(A, n);\
        kryptos_del_mp_value(A);\
        A = mod;\
        mod = NULL;\
    }\
}

#endif

#define kryptos_mp_me_mod_n(e, t, bn, A, m, n, div, mod) {\
    A = kryptos_mp_mul(&A, A);\
    div = kryptos_mp_div(A, n, &mod);\
    kryptos_del_mp_value(A);\
    kryptos_del_mp_value(div);\
    A = mod;\
     div = mod = NULL;\
    if ( ( ((e)->data[t] & (1 << (bn))) >> (bn) ) ) {\
        A = kryptos_mp_mul(&A, m);\
        div = kryptos_mp_div(A, n, &mod);\
        kryptos_del_mp_value(A);\
        kryptos_del_mp_value(div);\
        A = mod;\
        div = mod = NULL;\
    }\
}

#ifdef KRYPTOS_MP_ME_MOD_N_USE_MONTGOMERY_REDUCTION

    if (kryptos_mp_is_odd(n)) {
        for (t = e->data_size - 1; t >= 0; t--) {
#ifdef KRYPTOS_MP_U32_DIGIT
            kryptos_mp_me_mod_n_mont(e, t, 31, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 30, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 29, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 28, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 27, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 26, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 25, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 24, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 23, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 22, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 21, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 20, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 19, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 18, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 17, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 16, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 15, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 14, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 13, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 12, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 11, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 10, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t,  9, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t,  8, A, m, n, mod);
#endif
            kryptos_mp_me_mod_n_mont(e, t, 7, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 6, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 5, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 4, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 3, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 2, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 1, A, m, n, mod);
            kryptos_mp_me_mod_n_mont(e, t, 0, A, m, n, mod);
        }
    } else {
#endif
        for (t = e->data_size - 1; t >= 0; t--) {
#ifdef KRYPTOS_MP_U32_DIGIT
            kryptos_mp_me_mod_n(e, t, 31, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 30, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 29, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 28, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 27, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 26, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 25, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 24, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 23, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 22, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 21, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 20, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 19, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 18, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 17, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 16, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 15, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 14, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 13, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 12, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 11, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 10, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t,  9, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t,  8, A, m, n, div, mod);
#endif
            kryptos_mp_me_mod_n(e, t, 7, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 6, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 5, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 4, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 3, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 2, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 1, A, m, n, div, mod);
            kryptos_mp_me_mod_n(e, t, 0, A, m, n, div, mod);
        }
#ifdef KRYPTOS_MP_ME_MOD_N_USE_MONTGOMERY_REDUCTION
    }

#undef kryptos_mp_me_mod_n_mont
#endif

#undef kryptos_mp_me_mod_n

    return A;

}

kryptos_mp_value_t *kryptos_mp_rand(const size_t bits) {
    kryptos_mp_value_t *r;
    size_t d;

    r = kryptos_new_mp_value(kryptos_mp_byte2bit(kryptos_mp_bit2byte(bits)));

    if (r == NULL) {
        return NULL;
    }

    for (d = 0; d < r->data_size; d++) {
#ifndef KRYPTOS_MP_U32_DIGIT
        r->data[d] = kryptos_get_random_byte();
#else
        r->data[d] = (kryptos_u32_t) kryptos_get_random_byte() << 24 |
                     (kryptos_u32_t) kryptos_get_random_byte() << 16 |
                     (kryptos_u32_t) kryptos_get_random_byte() <<  8 |
                     (kryptos_u32_t) kryptos_get_random_byte();
#endif
    }

    return r;
}

kryptos_mp_value_t *kryptos_mp_gen_random(const kryptos_mp_value_t *n) {
    kryptos_mp_value_t *r = NULL, *r_div = NULL, *r_mod = NULL;
    ssize_t ri;

    if (n == NULL) {
        return NULL;
    }

    r = kryptos_new_mp_value(kryptos_mp_byte2bit(n->data_size));

    if (r == NULL) {
        return NULL;
    }

#ifndef KRYPTOS_MP_DIGIT_U32

    for (ri = r->data_size - 1; ri >= 0; ri--) {
        r->data[ri] = kryptos_get_random_byte();
    }

#else

    for (ri = r->data_size - 1; ri >= 0; ri--) {
        r->data[ri] = (kryptos_u32_t) kryptos_get_random_byte() << 24 |
                      (kryptos_u32_t) kryptos_get_random_byte() << 16 |
                      (kryptos_u32_t) kryptos_get_random_byte() <<  8 |
                      (kryptos_u32_t) kryptos_get_random_byte();
    }

#endif

    if ((r_div = kryptos_mp_div(r, n, &r_mod)) != NULL) {
        kryptos_del_mp_value(r_div);
    }

    kryptos_del_mp_value(r);

    return r_mod;
}

int kryptos_mp_is_prime(const kryptos_mp_value_t *n) {
    int is_prime = kryptos_mp_fermat_test(n, 7);

    if (is_prime) {
        // INFO(Rafael): Avoiding any Carmichael's number.
        return kryptos_mp_miller_rabin_test(n, 14);
    }

    return is_prime;
}

int kryptos_mp_miller_rabin_test(const kryptos_mp_value_t *n, const int sn) {
    kryptos_mp_value_t *k = NULL, *m = NULL, *n_1 = NULL, *_1 = NULL, *_0 = NULL,
                       *e = NULL, *p = NULL, *n_div = NULL, *n_mod = NULL, *a = NULL, *bs = NULL;
    int is_prime = 1;
    int s, pn;

    if (n == NULL) {
        return 0;
    }

    if (kryptos_mp_is_even(n)) {
        return 0;
    }

    a = kryptos_hex_value_as_mp("2", 1);

    if (a == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    if (kryptos_mp_eq(n, a)) {
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    // INFO(Rafael): Setting up some initial values.

    _1 = kryptos_hex_value_as_mp("1", 1); // 1.
    if (_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    n_1 = kryptos_assign_mp_value(&n_1, n);
    if (n_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    // INFO(Rafael): Step 1, finding n - 1, m and k.

    n_1 = kryptos_mp_sub(&n_1, _1); // n - 1.
    if (n_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    // INFO(Rafael): Now k and m.

    _0 = kryptos_hex_value_as_mp("0", 1);

    if (_0 == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    pn = 1;
    n_div = kryptos_mp_div_2p(n_1, pn, &n_mod);
    if ((k = kryptos_new_mp_value(kryptos_mp_byte2bit(4))) == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    do {
        // INFO(Rafael): Initially always should enter into this loop because n - 1 mod 2^1 is zero (n should be > 2 and odd).
        m = kryptos_assign_mp_value(&m, n_div); // temp m.
#ifndef KRYPTOS_MP_U32_DIGIT
        k->data[3] = pn >> 24;
        k->data[2] = (pn >> 16) & 0xFF;
        k->data[1] = (pn >>  8) & 0xFF;
        k->data[0] = pn & 0xFF;
#else
        k->data[0] = pn;
#endif
        if (m == NULL) {
            is_prime = 0;
            goto kryptos_mp_miller_rabin_test_epilogue;
        }
        kryptos_del_mp_value(n_div);
        kryptos_del_mp_value(n_mod);
        n_div = n_mod = NULL;
        pn++;
        n_div = kryptos_mp_div_2p(n_1, pn, &n_mod);
        if (n_div == NULL || n_mod == NULL) {
            is_prime = 0;
            goto kryptos_mp_miller_rabin_test_epilogue;
        }
    } while (kryptos_mp_eq(n_mod, _0));

    kryptos_del_mp_value(n_div);
    kryptos_del_mp_value(n_mod);
    n_div = n_mod = NULL;

    // INFO(Rafael): Now we got n - 1 = 2^k x m.

    // INFO(Rafael): Step 2, guessing a. Where 1 < a < n - 1.

    p = kryptos_assign_mp_value(&p, n_1);

    if (p == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    p = kryptos_mp_sub(&p, _1); // n - 2.

    if (p == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    if (!kryptos_mp_eq(p, _1)) {
        do {
            if (a != NULL) {
                kryptos_del_mp_value(a);
            }
            if ((a = kryptos_mp_gen_random(p)) == NULL) {
                is_prime = 0;
                goto kryptos_mp_miller_rabin_test_epilogue;
            }
        } while kryptos_mp_le(a, _1);
    } else {
        if ((a = kryptos_assign_mp_value(&a, p)) == NULL) {
            is_prime = 0;
            goto kryptos_mp_miller_rabin_test_epilogue;
        }
    }
    kryptos_del_mp_value(p);
    p = NULL;

    // INFO(Rafael): Step 3, b0 = a^m mod n.

    n_mod = kryptos_mp_me_mod_n(a, m, n);

    if (n_mod == NULL) {
        is_prime = 0;
        goto kryptos_mp_miller_rabin_test_epilogue;
    }

    is_prime = kryptos_mp_eq(n_mod, _1) || kryptos_mp_eq(n_mod, n_1); // INFO(Rafael): n - 1 means "-1".

    if (!is_prime) {
        if ((e = kryptos_hex_value_as_mp("2", 1)) == NULL) {
            is_prime = 0;
            goto kryptos_mp_miller_rabin_test_epilogue;
        }

        // INFO(Rafael): The last test failed let's calculate b_s .. b_sn.
        //               If bs = a^2 mod n = 1 is composite, -1 is prime, otherwise go ahead trying until s = sn.
        for (s = 0; s < sn && !is_prime; s++) {

            bs = kryptos_mp_me_mod_n(n_mod, e, n); // INFO(Rafael): bs = a^2 mod n.
            kryptos_del_mp_value(n_mod);
            n_mod = bs;

            if (n_mod == NULL) {
                is_prime = 0;
                goto kryptos_mp_miller_rabin_test_epilogue;
            }

            if (kryptos_mp_eq(n_mod, _1)) {
                // INFO(Rafael): Nevermind, it is composite.
                goto kryptos_mp_miller_rabin_test_epilogue;
            }

            is_prime = kryptos_mp_eq(n_mod, n_1);
        }
    }

kryptos_mp_miller_rabin_test_epilogue:

    if (a != NULL) {
        kryptos_del_mp_value(a);
    }

    if (e != NULL) {
        kryptos_del_mp_value(e);
    }

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (n_div != NULL) {
        kryptos_del_mp_value(n_div);
    }

    if (n_mod != NULL) {
        kryptos_del_mp_value(n_mod);
    }

    if (m != NULL) {
        kryptos_del_mp_value(m);
    }

    if (k != NULL) {
        kryptos_del_mp_value(k);
    }

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (_0 != NULL) {
        kryptos_del_mp_value(_0);
    }

    if (n_1 != NULL) {
        kryptos_del_mp_value(n_1);
    }

    return is_prime;
}

int kryptos_mp_fermat_test(const kryptos_mp_value_t *n, const int k) {
    kryptos_mp_value_t *a = NULL, *n_1 = NULL, *_1 = NULL, *p_mod = NULL, *n_2 = NULL;
    int i, is_prime = 1;

    if (n == NULL) {
        return 0;
    }

    a = kryptos_hex_value_as_mp("2", 1);

    if (a == NULL) {
        is_prime = 0;
        goto kryptos_mp_fermat_test_epilogue;
    }

    if (kryptos_mp_le(n, a)) {
        is_prime = kryptos_mp_eq(n, a);
        goto kryptos_mp_fermat_test_epilogue;
    }

    kryptos_del_mp_value(a);
    a = NULL;

    if (kryptos_mp_is_even(n)) { // WARN(Rafael): Almost like that old 80's song "Don't get mad AND AIN'T even..." ;)
        return 0;
    }

    _1 = kryptos_hex_value_as_mp("1", 1);

    if (_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_fermat_test_epilogue;
    }

    n_1 = kryptos_assign_mp_value(&n_1, n);

    if (n_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_fermat_test_epilogue;
    }

    n_1 = kryptos_mp_sub(&n_1, _1);

    if (n_1 == NULL) {
        is_prime = 0;
        goto kryptos_mp_fermat_test_epilogue;
    }

    n_2 = kryptos_assign_mp_value(&n_2, n_1);

    if (n_2 == NULL) {
        is_prime = 0;
        goto kryptos_mp_fermat_test_epilogue;
    }

    n_2 = kryptos_mp_sub(&n_2, _1);

    for (i = 0; i < k && is_prime; i++) {
        a = kryptos_mp_gen_random(n_2);
        a = kryptos_mp_add(&a, _1);

        if (a == NULL) {
            is_prime = 0;
            goto kryptos_mp_fermat_test_epilogue;
        }

        p_mod = kryptos_mp_me_mod_n(a, n_1, n);

        kryptos_del_mp_value(a);
        a = NULL;

        if (p_mod == NULL) {
            is_prime = 0;
            goto kryptos_mp_fermat_test_epilogue;
        }

        is_prime = kryptos_mp_eq(p_mod, _1);

        kryptos_del_mp_value(p_mod);
        p_mod = NULL;
    }

kryptos_mp_fermat_test_epilogue:

    // INFO(Rafael): Housekeeping

    if (a != NULL) {
        kryptos_del_mp_value(a);
    }

    if (p_mod != NULL) {
        kryptos_del_mp_value(p_mod);
    }

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (n_1 != NULL) {
        kryptos_del_mp_value(n_1);
    }

    if (n_2 != NULL) {
        kryptos_del_mp_value(n_2);
    }

    // INFO(Rafael): If you have picked only Fermat liars, sorry! ;)
    return is_prime;
}

kryptos_mp_value_t *kryptos_mp_lsh(kryptos_mp_value_t **a, const int level) {
    int l;
    ssize_t d;
    kryptos_u8_t cb, lc;
    kryptos_mp_value_t *t = NULL;

    if (a == NULL || (*a) == NULL) {
        return NULL;
    }

    t = kryptos_new_mp_value(kryptos_mp_byte2bit((*a)->data_size) + level);

    if (t == NULL) {
        goto kryptos_mp_lsh_epilogue;
    }

    t = kryptos_assign_mp_value(&t, *a);

    for (l = 0; l < level; l++) {
        cb = lc = 0;
        for (d = 0; d < t->data_size; d++, lc = cb) {
#ifndef KRYPTOS_MP_U32_DIGIT
            cb = t->data[d] >> 7;
#else
            cb = t->data[d] >> 31;
#endif
            t->data[d] = (t->data[d] << 1) | lc;
        }
    }

kryptos_mp_lsh_epilogue:

    kryptos_del_mp_value(*a);
    *a = t;

    return (*a);
}

kryptos_mp_value_t *kryptos_mp_rsh_op(kryptos_mp_value_t **a, const int level, const int signed_op) {
    int l;
    ssize_t d;
    kryptos_u8_t cb, lc;
    kryptos_mp_value_t *t = NULL;
#ifndef KRYPTOS_MP_U32_DIGIT
    kryptos_u8_t signal = 0;
#else
    kryptos_u32_t signal = 0;
#endif

    if (a == NULL || (*a) == NULL) {
        return NULL;
    }

    t = kryptos_new_mp_value(kryptos_mp_byte2bit((*a)->data_size));

    if (t == NULL) {
        return NULL;
    }

    if (signed_op) {
#ifndef KRYPTOS_MP_U32_DIGIT
        signal = (kryptos_mp_is_neg(*a)) << 7;
#else
        signal = (kryptos_mp_is_neg(*a)) << 31;
#endif
    }

    t = kryptos_assign_mp_value(&t, *a);

    for (l = 0; l < level; l++) {
        cb = lc = 0;
        for (d = t->data_size - 1; d >= 0; d--, lc = cb) {
            cb = t->data[d] & 1;
#ifndef KRYPTOS_MP_U32_DIGIT
            t->data[d] = (t->data[d] >> 1) | (lc << 7);
#else
            t->data[d] = (t->data[d] >> 1) | (lc << 31);
#endif
        }
        t->data[t->data_size - 1] |= signal;
    }

//kryptos_mp_rsh_epilogue:

    kryptos_del_mp_value(*a);

    (*a) = kryptos_new_mp_value(kryptos_mp_byte2bit(t->data_size));

    d = 0;
    while (d < t->data_size) {
        (*a)->data[d] = t->data[d];
        d++;
    }

    kryptos_del_mp_value(t);

    return (*a);
}

kryptos_mp_value_t *kryptos_mp_gen_prime(const size_t bitsize) {
    kryptos_mp_value_t *pn = NULL, *_2 = NULL, *p = NULL;
    ssize_t d;
    int is_prime = 0;
#ifdef KRYPTOS_MP_U32_DIGIT
    size_t bytesize = 0;
#endif

#ifndef KRYPTOS_MP_U32_DIGIT
    pn = kryptos_new_mp_value(bitsize);
#else
    bytesize = kryptos_mp_bit2byte(bitsize);
    pn = kryptos_new_mp_value(kryptos_mp_byte2bit(bytesize));
#endif
    _2 = kryptos_hex_value_as_mp("2", 1);

    if (pn == NULL || _2 == NULL) {
        return NULL;
    }

    while (!is_prime) {

        for (d = 0; d < pn->data_size; d++) {
#ifndef KRYPTOS_MP_U32_DIGIT
            pn->data[d] = kryptos_get_random_byte();
#else
            pn->data[d] = ((kryptos_u32_t)kryptos_get_random_byte() << 24) |
                          ((kryptos_u32_t)kryptos_get_random_byte() << 16) |
                          ((kryptos_u32_t)kryptos_get_random_byte() <<  8) |
                          kryptos_get_random_byte();
#endif
        }

        pn->data[0] |= 0x1;

#ifdef KRYPTOS_MP_U32_DIGIT

        d = 0;

        while (!(is_prime = kryptos_mp_gen_prime_small_primes_test(pn, NULL)) && d < 0xFF) {
            if (p == NULL) {
                pn = kryptos_mp_add(&pn, _2);
            } else {
                pn = kryptos_mp_add(&pn, p);
                pn->data[0] |= 0x1;
                kryptos_del_mp_value(p);
                p = NULL;
            }

            if (!is_prime) {
                continue;
            }

            is_prime = kryptos_mp_fermat_test(pn, 2);

            if (!is_prime) {
                pn = kryptos_mp_add(&pn, _2);
            }
            d++;
        }

        if (!is_prime) {
            continue;
        }

#endif
        is_prime = kryptos_mp_miller_rabin_test(pn, 5);
    }

    kryptos_del_mp_value(_2);

    return pn;
}

/*
kryptos_mp_value_t *kryptos_mp_gen_prime_2k1(const size_t k_bitsize) {
    // INFO(Rafael): This function will generate a p = 2k + 1. k is also a prime.
    kryptos_mp_value_t *k = NULL;
    kryptos_mp_value_t *p = NULL, *_2 = NULL, *_1 = NULL;
    int is_prime = 0;

    if ((_1 = kryptos_hex_value_as_mp("1", 1)) == NULL) {
        goto kryptos_mp_gen_prime_2k1_epilogue;
    }

    if ((_2 = kryptos_hex_value_as_mp("2", 1)) == NULL) {
        goto kryptos_mp_gen_prime_2k1_epilogue;
    }

    do {
        if ((k = kryptos_mp_gen_prime(k_bitsize)) == NULL) {
            goto kryptos_mp_gen_prime_2k1_epilogue;
        }
printf("k = ");kryptos_print_mp(k);
        if ((p = kryptos_assign_mp_value(&p, k)) == NULL) {
            goto kryptos_mp_gen_prime_2k1_epilogue;
        }

        if ((p = kryptos_mp_mul(&p, _2)) == NULL) {
            goto kryptos_mp_gen_prime_2k1_epilogue;
        }

        if((p = kryptos_mp_add(&p, _1)) == NULL) {
            goto kryptos_mp_gen_prime_2k1_epilogue;
        }
printf("p = ");kryptos_print_mp(p);
        kryptos_del_mp_value(k);
        k = NULL;

        if ((is_prime = kryptos_mp_is_prime(p)) == 0) {
            kryptos_del_mp_value(p);
            p = NULL;
        }

    } while (!is_prime);


kryptos_mp_gen_prime_2k1_epilogue:

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (_2 != NULL) {
        kryptos_del_mp_value(_2);
    }

    if (k != NULL) {
        kryptos_del_mp_value(k);
    }

    if (!is_prime && p != NULL) {
        kryptos_del_mp_value(p);
        p = NULL;
    }

    return p;
}
*/

kryptos_mp_value_t *kryptos_mp_montgomery_reduction(const kryptos_mp_value_t *x, const kryptos_mp_value_t *y) {
    // INFO(Rafael): This calculates ZR mod Y.
    kryptos_mp_value_t *z = NULL, *r = NULL, *b = NULL, *d = NULL;
    ssize_t rdn, rd;

    if (x == NULL || y == NULL) {
        return NULL;
    }

    if ((z = kryptos_mp_montgomery_reduction_2kx_mod_y(x, y)) == NULL) {
        return NULL;
    }

    b = kryptos_hex_value_as_mp("1", 1);
    b = kryptos_mp_lsh(&b, kryptos_mp_byte2bit(x->data_size));

    if ((d = kryptos_mp_div(b, y, &r)) == NULL) {
        goto kryptos_mp_montgomery_reduction_epilogue;
    }

    kryptos_del_mp_value(d);

    if ((z = kryptos_mp_mul(&z, r)) == NULL) {
        goto kryptos_mp_montgomery_reduction_epilogue;
    }

    kryptos_del_mp_value(r);
    r = NULL;

    if ((d = kryptos_mp_div(z, y, &r)) == NULL) {
        goto kryptos_mp_montgomery_reduction_epilogue;
    }

    kryptos_del_mp_value(d);

    if (r != NULL) {
        for (rdn = r->data_size - 1; rdn >= 0 && r->data[rdn] == 0; rdn--)
            ;

        if (rdn > - 1) {
            d = r;
            r = kryptos_new_mp_value((rdn + 1) << 3);
            for (rd = 0; rd <= rdn; rd++) {
                r->data[rd] = d->data[rd];
            }
            kryptos_del_mp_value(d);
        }
    }

kryptos_mp_montgomery_reduction_epilogue:

    if (z != NULL) {
        kryptos_del_mp_value(z);
    }

    if (b != NULL) {
        kryptos_del_mp_value(b);
    }

    return r;
}

static kryptos_mp_value_t *kryptos_mp_montgomery_reduction_2kx_mod_y(const kryptos_mp_value_t *x,
                                                                     const kryptos_mp_value_t *y) {
    // INFO(Rafael): Calculates 2^-K X mod Y. K is the bit length.
    kryptos_mp_value_t *xt = NULL;
    ssize_t k, ks;

    if (x == NULL || y == NULL) {
        return NULL;
    }

    xt = kryptos_assign_mp_value(&xt, x);
    ks = kryptos_mp_byte2bit(xt->data_size);

    for (k = 0; k < ks; k++) {
        if (kryptos_mp_is_odd(xt)) {
            xt = kryptos_mp_add(&xt, y);
        }
        xt = kryptos_mp_rsh(&xt, 1);
    }

    if (kryptos_mp_ge(xt, y)) {
        xt = kryptos_mp_sub(&xt, y);
    }

    return xt;
}

kryptos_mp_value_t *kryptos_mp_gcd(const kryptos_mp_value_t *a, const kryptos_mp_value_t *b) {
    kryptos_mp_value_t *x = NULL, *y = NULL;
    kryptos_mp_value_t *g = NULL, *t = NULL, *gcd = NULL, *_0 = NULL;

    if (a == NULL || b == NULL) {
        return NULL;
    }

    if (kryptos_mp_gt(a, b)) {
        x = kryptos_assign_mp_value(&x, a);
        y = kryptos_assign_mp_value(&y, b);
    } else {
        x = kryptos_assign_mp_value(&x, b);
        y = kryptos_assign_mp_value(&y, a);
    }

    if ((g = kryptos_hex_value_as_mp("1", 1)) == NULL) {
        goto kryptos_mp_gcd_epilogue;
    }

    while (kryptos_mp_is_even(x) && kryptos_mp_is_even(y)) {
        x = kryptos_mp_rsh(&x, 1);
        y = kryptos_mp_rsh(&y, 1);
        g = kryptos_mp_lsh(&g, 1);
    }

    if ((_0 = kryptos_hex_value_as_mp("0", 1)) == NULL) {
        goto kryptos_mp_gcd_epilogue;
    }

    while (kryptos_mp_ne(x, _0)) {
        while (kryptos_mp_is_even(x)) {
            x = kryptos_mp_rsh(&x, 1);
        }

        while (kryptos_mp_is_even(y)) {
            y = kryptos_mp_rsh(&y, 1);
        }

        if (kryptos_mp_lt(y, x)) {
            t = kryptos_assign_mp_value(&t, x);
            t = kryptos_mp_sub(&t, y);
        } else {
            t = kryptos_assign_mp_value(&t, y);
            t = kryptos_mp_sub(&t, x);
        }

        t = kryptos_mp_rsh(&t, 1);

        if (kryptos_mp_ge(x, y)) {
            x = kryptos_assign_mp_value(&x, t);
        } else {
            y = kryptos_assign_mp_value(&y, t);
        }
    }

    gcd = kryptos_assign_mp_value(&gcd, g);
    gcd = kryptos_mp_mul(&gcd, y);

kryptos_mp_gcd_epilogue:

    if (x != NULL) {
        kryptos_del_mp_value(x);
    }

    if (y != NULL) {
        kryptos_del_mp_value(y);
    }

    if (g != NULL) {
        kryptos_del_mp_value(g);
    }

    if (t != NULL) {
        kryptos_del_mp_value(t);
    }

    if (_0 != NULL) {
        kryptos_del_mp_value(_0);
    }

    return gcd;
}

#ifdef KRYPTOS_MP_BINARY_MODINV

/*kryptos_mp_value_t *kryptos_mp_modinv(const kryptos_mp_value_t *ua, const kryptos_mp_value_t *m) {
    kryptos_mp_value_t *g = NULL, *x = NULL, *y = NULL, *A = NULL, *B = NULL, *C = NULL, *D = NULL,
                       *u = NULL, *v = NULL, *_0 = NULL, *_1 = NULL;
    kryptos_mp_value_t *a = NULL, *b = NULL, *gcd = NULL;
    int has_converged;

    _0 = kryptos_hex_value_as_mp("0", 1);
    _1 = kryptos_hex_value_as_mp("1", 1);
    g = kryptos_hex_value_as_mp("1", 1);
    x = kryptos_assign_mp_value(&x, ua);
    y = kryptos_assign_mp_value(&y, m);

    while (kryptos_mp_is_even(x) && kryptos_mp_is_even(y)) {
        x = kryptos_mp_signed_rsh(&x, 1);
        y = kryptos_mp_signed_rsh(&y, 1);
        g = kryptos_mp_lsh(&g, 1);
    }

    u = kryptos_assign_mp_value(&u, x);
    v = kryptos_assign_mp_value(&v, y);

    //A = kryptos_new_mp_value(m->data_size << 3);
    //B = kryptos_new_mp_value(m->data_size << 3);
    //C = kryptos_new_mp_value(m->data_size << 3);
    //D = kryptos_new_mp_value(m->data_size << 3);

    //A = kryptos_assign_mp_value(&A, _1);
    //B = kryptos_assign_mp_value(&B, _0);
    //C = kryptos_assign_mp_value(&C, _0);
    //D = kryptos_assign_mp_value(&A, _1);
    A = kryptos_hex_value_as_mp("1", 1);
    B = kryptos_hex_value_as_mp("0", 1);
    C = kryptos_hex_value_as_mp("0", 1);
    D = kryptos_hex_value_as_mp("1", 1);

    do {
        printf("u = "); kryptos_print_mp(u);
        printf("v = "); kryptos_print_mp(v);
        printf("A = "); kryptos_print_mp(A);
        printf("B = "); kryptos_print_mp(B);
        printf("C = "); kryptos_print_mp(C);
        printf("D = "); kryptos_print_mp(D);
        printf("x = "); kryptos_print_mp(x);
        printf("y = "); kryptos_print_mp(y);
        printf("--\n");
        while (kryptos_mp_is_even(u)) {
            u = kryptos_mp_signed_rsh(&u, 1);
            if (kryptos_mp_is_even(A) && kryptos_mp_is_even(B)) {
                printf("\tA = "); kryptos_print_mp(A);
                printf("\tB = "); kryptos_print_mp(B);
                A = kryptos_mp_signed_rsh(&A, 1);
                B = kryptos_mp_signed_rsh(&B, 1);
                printf("\tA' = "); kryptos_print_mp(A);
                printf("\tB' = "); kryptos_print_mp(B);
            } else {
                printf("\tA = "); kryptos_print_mp(A);
                printf("\ty = "); kryptos_print_mp(y);
                A = kryptos_mp_add(&A, y);
                A = kryptos_mp_signed_rsh(&A, 1);
                printf("\tA'= "); kryptos_print_mp(A);
                printf("\tB = "); kryptos_print_mp(B);
                printf("\tx = "); kryptos_print_mp(x);
                B = kryptos_mp_sub(&B, x);
                B = kryptos_mp_signed_rsh(&B, 1);
                printf("\tB' = "); kryptos_print_mp(B);
            }
            printf("--\n");
        }

        while (kryptos_mp_is_even(v)) {
            v = kryptos_mp_signed_rsh(&v, 1);
            if (kryptos_mp_is_even(C) && kryptos_mp_is_even(D)) {
                printf("\tC = "); kryptos_print_mp(C);
                printf("\tD = "); kryptos_print_mp(D);
                C = kryptos_mp_signed_rsh(&C, 1);
                D = kryptos_mp_signed_rsh(&D, 1);
                printf("\tC' = "); kryptos_print_mp(C);
                printf("\tD' = "); kryptos_print_mp(D);
            } else {
                printf("\tC = "); kryptos_print_mp(C);
                printf("\ty = "); kryptos_print_mp(y);
                C = kryptos_mp_add(&C, y);
                C = kryptos_mp_signed_rsh(&C, 1);
                printf("\tC'= "); kryptos_print_mp(C);
                printf("\tD = "); kryptos_print_mp(D);
                printf("\tx = "); kryptos_print_mp(x);
                D = kryptos_mp_sub(&D, x);
                printf("\tD' = "); kryptos_print_mp(D);
                D = kryptos_mp_signed_rsh(&D, 1);
                printf("\tD'' = "); kryptos_print_mp(D);
            }
        }

        if (kryptos_mp_ge(u, v)) {
            printf("\tuL = "); kryptos_print_mp(u);
            printf("\tC = "); kryptos_print_mp(C);
            printf("\tAL = "); kryptos_print_mp(A);
            printf("\tBL = "); kryptos_print_mp(B);
//            printf("\t\tD = "); kryptos_print_mp(D);
            u = kryptos_mp_sub(&u, v);
            A = kryptos_mp_sub(&A, C);
            B = kryptos_mp_sub(&B, D);
            printf("\tuL' = "); kryptos_print_mp(u);
            printf("\tAL' = "); kryptos_print_mp(A);
            printf("\tBL' = "); kryptos_print_mp(B);
        } else {
            printf("\tvL = "); kryptos_print_mp(v);
            printf("\tA = "); kryptos_print_mp(A);
            printf("\tCL = "); kryptos_print_mp(C);
            printf("\tDL = "); kryptos_print_mp(D);
            v = kryptos_mp_sub(&v, u);
            C = kryptos_mp_sub(&C, A);
            D = kryptos_mp_sub(&D, B);
            printf("\tvL' = "); kryptos_print_mp(v);
            printf("\tCL' = "); kryptos_print_mp(C);
            printf("\tDL' = "); kryptos_print_mp(D);
        }

        if ((has_converged = kryptos_mp_eq(u, _0))) {
            a = kryptos_assign_mp_value(&a, C);
            b = kryptos_assign_mp_value(&b, D);
            gcd = kryptos_assign_mp_value(&gcd, g);
            gcd = kryptos_mp_signed_mul(&gcd, v);
        }
    } while (!has_converged);

    if (kryptos_mp_is_neg(a)) {
        a = kryptos_mp_add(&a, m);
    }

kryptos_mp_modinv_epilogue:

    printf("a = "); kryptos_print_mp(a);
    printf("b = "); kryptos_print_mp(b);
    printf("gcd = "); kryptos_print_mp(gcd);

    if (!kryptos_mp_eq(gcd, _1)) {
        // INFO(Rafael): There is no multiplicative inverse.
        kryptos_del_mp_value(a);
        a = NULL;
    }

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (_0 != NULL) {
        kryptos_del_mp_value(_0);
    }

    if (g != NULL) {
        kryptos_del_mp_value(g);
    }

    if (x != NULL) {
        kryptos_del_mp_value(x);
    }

    if (y != NULL) {
        kryptos_del_mp_value(y);
    }

    if (A != NULL) {
        kryptos_del_mp_value(A);
    }

    if (B != NULL) {
        kryptos_del_mp_value(B);
    }

    if (C != NULL) {
        kryptos_del_mp_value(C);
    }

    if (D != NULL) {
        kryptos_del_mp_value(D);
    }

    if (u != NULL) {
        kryptos_del_mp_value(u);
    }

    if (v != NULL) {
        kryptos_del_mp_value(v);
    }

    if (gcd != NULL) {
        kryptos_del_mp_value(gcd);
    }

    if (b != NULL) {
        kryptos_del_mp_value(b);
    }

    if (a != NULL && kryptos_mp_is_neg(a)) {
        a = kryptos_mp_add(&a, m);
    }

    return a;
}*/

#else

kryptos_mp_value_t *kryptos_mp_modinv(const kryptos_mp_value_t *u, const kryptos_mp_value_t *v) {
    kryptos_mp_value_t *inv = NULL, *u1 = NULL, *u3 = NULL, *v1 = NULL, *v3 = NULL, *t1 = NULL, *t3 = NULL, *q = NULL;
    kryptos_mp_value_t *_1 = NULL, *_0 = NULL;
    char iter = 1;

    // TODO(Rafael): If the v is prime use the Fermat's little theorem instead of the Extended Euclidean.

    KRYPTOS_MP_ABORT_WHEN_NULL(_1 = kryptos_hex_value_as_mp("1", 1), kryptos_mp_modinv_epilogue);
    KRYPTOS_MP_ABORT_WHEN_NULL(_0 = kryptos_hex_value_as_mp("0", 1), kryptos_mp_modinv_epilogue);

    KRYPTOS_MP_ABORT_WHEN_NULL(u1 = kryptos_assign_mp_value(&u1, _1), kryptos_mp_modinv_epilogue);
    KRYPTOS_MP_ABORT_WHEN_NULL(u3 = kryptos_assign_mp_value(&u3, u), kryptos_mp_modinv_epilogue);
    KRYPTOS_MP_ABORT_WHEN_NULL(v1 = kryptos_assign_mp_value(&v1, _0), kryptos_mp_modinv_epilogue);
    KRYPTOS_MP_ABORT_WHEN_NULL(v3 = kryptos_assign_mp_value(&v3, v), kryptos_mp_modinv_epilogue);

    while (kryptos_mp_ne(v3, _0)) {
        KRYPTOS_MP_ABORT_WHEN_NULL(q = kryptos_mp_div(u3, v3, &t3), kryptos_mp_modinv_epilogue);
        KRYPTOS_MP_ABORT_WHEN_NULL(t1 = kryptos_assign_mp_value(&t1, q), kryptos_mp_modinv_epilogue);
        KRYPTOS_MP_ABORT_WHEN_NULL(t1 = kryptos_mp_mul(&t1, v1), kryptos_mp_modinv_epilogue);
        KRYPTOS_MP_ABORT_WHEN_NULL(t1 = kryptos_mp_add(&t1, u1), kryptos_mp_modinv_epilogue);
        KRYPTOS_MP_ABORT_WHEN_NULL(u1 = kryptos_assign_mp_value(&u1, v1), kryptos_mp_modinv_epilogue);
        KRYPTOS_MP_ABORT_WHEN_NULL(v1 = kryptos_assign_mp_value(&v1, t1), kryptos_mp_modinv_epilogue);
        KRYPTOS_MP_ABORT_WHEN_NULL(u3 = kryptos_assign_mp_value(&u3, v3), kryptos_mp_modinv_epilogue);
        KRYPTOS_MP_ABORT_WHEN_NULL(v3 = kryptos_assign_mp_value(&v3, t3), kryptos_mp_modinv_epilogue);
        kryptos_del_mp_value(q);
        kryptos_del_mp_value(t3);
        q = t3 = NULL;
        iter = ~iter;
    }

    if (kryptos_mp_eq(u3, _1)) {
        if (iter < 0) {
            KRYPTOS_MP_ABORT_WHEN_NULL(inv = kryptos_assign_mp_value(&inv, v), kryptos_mp_modinv_epilogue);
            KRYPTOS_MP_ABORT_WHEN_NULL(inv = kryptos_mp_sub(&inv, u1), kryptos_mp_modinv_epilogue);
        } else {
            KRYPTOS_MP_ABORT_WHEN_NULL(inv = kryptos_assign_mp_value(&inv, u1), kryptos_mp_modinv_epilogue);
        }
    }

kryptos_mp_modinv_epilogue:

    if (_1 != NULL) {
        kryptos_del_mp_value(_1);
    }

    if (_0 != NULL) {
        kryptos_del_mp_value(_0);
    }

    if (u1 != NULL) {
        kryptos_del_mp_value(u1);
    }

    if (u3 != NULL) {
        kryptos_del_mp_value(u3);
    }

    if (v1 != NULL) {
        kryptos_del_mp_value(v1);
    }

    if (v3 != NULL) {
        kryptos_del_mp_value(v3);
    }

    if (t1 != NULL) {
        kryptos_del_mp_value(t1);
    }

    if (t3 != NULL) {
        kryptos_del_mp_value(t3);
    }

    if (q != NULL) {
        kryptos_del_mp_value(q);
    }

    return inv;
}

#endif

kryptos_mp_value_t *kryptos_mp_not(kryptos_mp_value_t *n) {
    ssize_t d;

    if (n == NULL) {
        return NULL;
    }

    for (d = n->data_size - 1; d >= 0; d--) {
        n->data[d] = ~n->data[d];
    }

    return n;
}

kryptos_mp_value_t *kryptos_mp_inv_signal(kryptos_mp_value_t *n) {
    kryptos_mp_value_t *_1 = NULL;

    if (n == NULL) {
        return NULL;
    }

    if ((n = kryptos_mp_not(n)) == NULL) {
        return NULL;
    }

    if ((_1 = kryptos_hex_value_as_mp("1", 1)) == NULL) {
        return NULL;
    }

    if ((n = kryptos_mp_add(&n, _1)) == NULL) {
        kryptos_del_mp_value(_1);
        return NULL;
    }

    kryptos_del_mp_value(_1);

    return n;
}
/*
kryptos_mp_value_t *kryptos_mp_signed_sub(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src) {
    // TODO(Rafael): Make this code resilient to NULL returns.
    int is_d_neg, is_s_neg, neg = 0;
    kryptos_mp_value_t *d = NULL, *s = NULL;
    size_t dsize;

    if (dest == NULL || src == NULL) {
        return NULL;
    }

    d = kryptos_assign_mp_value(&d, *dest);
    s = kryptos_assign_mp_value(&s, src);

    is_d_neg = kryptos_mp_is_neg(d);
    is_s_neg = kryptos_mp_is_neg(s);

    if (is_d_neg == is_s_neg) {
        // INFO(Rafael): Same signals.
        if (is_d_neg) {
            d = kryptos_mp_inv_signal(d);
            s = kryptos_mp_inv_signal(s);
        }

        if (kryptos_mp_gt(d, s)) {
            d = kryptos_mp_sub(&d, s);
            neg = is_d_neg;
        } else {
            s = kryptos_mp_sub(&s, d);
            d = kryptos_assign_mp_value(&d, s);
            neg = (is_s_neg == 0);
        }

//        if (neg) {
//            d = kryptos_mp_inv_signal(d);
//        }

    } else {
        // INFO(Rafael): Different signals.
        if (is_d_neg) {
            d = kryptos_mp_inv_signal(d);
        }

        if (is_s_neg) {
            s = kryptos_mp_inv_signal(s);
        }

        d = kryptos_mp_add(&d, s);

        neg = (kryptos_mp_gt(d, s) ? is_d_neg : is_s_neg) && !kryptos_mp_is_neg(d);

//        if (neg && !kryptos_mp_is_neg(d)) {
//            d = kryptos_mp_inv_signal(d);
//        }
    }

kryptos_mp_signed_sub_epilogue:

    if (d != NULL) {
        if (src->data_size > (*dest)->data_size) {
            dsize = src->data_size;
        } else {
            dsize = (*dest)->data_size;
        }
        kryptos_del_mp_value(*dest);
        (*dest) = kryptos_new_mp_value(dsize << 3);
        (*dest) = kryptos_assign_mp_value(dest, d);
        if (neg) {
            *dest = kryptos_mp_inv_signal(*dest);
        }
        kryptos_del_mp_value(d);
    }

    if (s != NULL) {
        kryptos_del_mp_value(s);
    }

    return (*dest);
}

kryptos_mp_value_t *kryptos_mp_signed_add(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src) {
    // TODO(Rafael): Make this code resilient to NULL returns.
    int is_d_neg, is_s_neg, neg = 0;
    kryptos_mp_value_t *d = NULL, *s = NULL;
    size_t dsize;

    if (dest == NULL || src == NULL) {
        return NULL;
    }

    d = kryptos_assign_mp_value(&d, *dest);
    s = kryptos_assign_mp_value(&s, src);

    is_d_neg = kryptos_mp_is_neg(d);
    is_s_neg = kryptos_mp_is_neg(s);

    if (is_d_neg == is_s_neg) {
        // INFO(Rafael): Same signals.
        if (is_d_neg) {
            d = kryptos_mp_inv_signal(d);
            s = kryptos_mp_inv_signal(s);
            neg = 1;
        }
        d = kryptos_mp_add(&d, s);
//        if (neg) {
//            d = kryptos_mp_inv_signal(d);
//        }
    } else {
        // INFO(Rafael): Different signals.
        if (is_d_neg) {
            d = kryptos_mp_inv_signal(d);
        }

        if (is_s_neg) {
            s = kryptos_mp_inv_signal(s);
        }

        if (kryptos_mp_gt(d, s)) {
            d = kryptos_mp_sub(&d, s);
            neg = is_d_neg;
        } else {
            s = kryptos_mp_sub(&s, d);
            d = kryptos_assign_mp_value(&d, s);
            neg = is_s_neg;
        }

//        if (neg) {
//            d = kryptos_mp_inv_signal(d);
//        }
    }

kryptos_mp_signed_add_epilogue:

    if (d != NULL) {
        if (src->data_size > (*dest)->data_size) {
            dsize = src->data_size;
        } else {
            dsize = (*dest)->data_size;
        }
        kryptos_del_mp_value(*dest);
        (*dest) = kryptos_new_mp_value(dsize << 3);
        (*dest) = kryptos_assign_mp_value(dest, d);
        if (neg) {
            *dest = kryptos_mp_inv_signal(*dest);
        }
        kryptos_del_mp_value(d);
    }

    if (s != NULL) {
        kryptos_del_mp_value(s);
    }

    return (*dest);
}

kryptos_mp_value_t *kryptos_mp_signed_mul(kryptos_mp_value_t **dest, const kryptos_mp_value_t *src) {
    int is_d_neg, is_s_neg;
    kryptos_mp_value_t *s = NULL, *d = NULL;

    if (dest == NULL || src == NULL) {
        return NULL;
    }

    KRYPTOS_MP_ABORT_WHEN_NULL(d = kryptos_assign_mp_value(&d, *dest), kryptos_mp_signed_mul_epilogue);

    KRYPTOS_MP_ABORT_WHEN_NULL(s = kryptos_assign_mp_value(&s, src), kryptos_mp_signed_mul_epilogue);

    if ((is_d_neg = kryptos_mp_is_neg(d)) == 1) {
        KRYPTOS_MP_ABORT_WHEN_NULL(d = kryptos_mp_inv_signal(d), kryptos_mp_signed_mul_epilogue);
    }

    if ((is_s_neg = kryptos_mp_is_neg(s)) == 1) {
        KRYPTOS_MP_ABORT_WHEN_NULL(s = kryptos_mp_inv_signal(s), kryptos_mp_signed_mul_epilogue);
    }

    KRYPTOS_MP_ABORT_WHEN_NULL(d = kryptos_mp_mul(&d, s), kryptos_mp_signed_mul_epilogue);

    if (is_d_neg != is_s_neg) {
        KRYPTOS_MP_ABORT_WHEN_NULL(d = kryptos_mp_inv_signal(d), kryptos_mp_signed_mul_epilogue);
    }

    KRYPTOS_MP_ABORT_WHEN_NULL((*dest) = kryptos_assign_mp_value(dest, d), kryptos_mp_signed_mul_epilogue);

kryptos_mp_signed_mul_epilogue:

    if (d != NULL) {
        kryptos_del_mp_value(d);
    }

    if (s != NULL) {
        kryptos_del_mp_value(s);
    }

    return (*dest);
}*/

static int kryptos_mp_gen_prime_small_primes_test(const kryptos_mp_value_t *n, kryptos_mp_value_t **prime) {
    size_t sp;
    kryptos_mp_value_t *p = NULL, *q = NULL, *r = NULL, *_0 = NULL;
    int test = 0;

    KRYPTOS_MP_ABORT_WHEN_NULL(_0 = kryptos_hex_value_as_mp("0", 1), kryptos_mp_gen_prime_small_primes_test_epilogue);

    for (sp = 0; sp < g_kryptos_mp_small_primes_nr; sp++) {
        KRYPTOS_MP_ABORT_WHEN_NULL(p = kryptos_hex_value_as_mp(g_kryptos_mp_small_primes[sp],
                                                               strlen(g_kryptos_mp_small_primes[sp])),
                                   kryptos_mp_gen_prime_small_primes_test_epilogue);

        KRYPTOS_MP_ABORT_WHEN_NULL(q = kryptos_mp_div(n, p, &r), kryptos_mp_gen_prime_small_primes_test_epilogue);
        if (kryptos_mp_eq(r, _0)) {
            if (prime != NULL) {
                *prime = p;
                p = NULL;
            }
            goto kryptos_mp_gen_prime_small_primes_test_epilogue;
        }

        kryptos_del_mp_value(q);
        kryptos_del_mp_value(r);
        kryptos_del_mp_value(p);
        p = q = r = NULL;
    }

    test = 1;

kryptos_mp_gen_prime_small_primes_test_epilogue:

    if (q != NULL) {
        kryptos_del_mp_value(q);
    }

    if (r != NULL) {
        kryptos_del_mp_value(r);
    }

    if (p != NULL) {
        kryptos_del_mp_value(p);
    }

    if (_0 != NULL) {
        kryptos_del_mp_value(_0);
    }

    return test;
}

kryptos_mp_value_t *kryptos_raw_buffer_as_mp(const kryptos_u8_t *buf, const size_t buf_size) {
    kryptos_mp_value_t *mp = NULL;
    char *hex = NULL, *hp, *hp_end;
    size_t hex_size;
    const kryptos_u8_t *bp, *bp_end;

    if (buf == NULL || buf_size == 0) {
        return NULL;
    }

    hex_size = buf_size << 1;
    hex = kryptos_newseg(hex_size + 1);

    if (hex == NULL) {
        return NULL;
    }

    bp = buf;
    bp_end = bp + buf_size;

    hp = hex;
    hp_end = hp + hex_size;
    *hp_end = 0;

    while (bp != bp_end && hp != hp_end) {
        *hp = kryptos_mp_nbx(*bp >> 4);
        *(hp + 1) = kryptos_mp_nbx(*bp & 0x0F);
        hp += 2;
        bp++;
    }

    mp = kryptos_hex_value_as_mp(hex, hex_size);

    memset(hex, 0, hex_size);
    kryptos_freeseg(hex);

    return mp;
}

#undef kryptos_mp_xnb

#undef kryptos_mp_nbx

#undef kryptos_mp_max_min

#undef KRYPTOS_MP_MULTIBYTE_FLOOR

#undef kryptos_mp_get_u32_from_mp

#undef kryptos_mp_put_u32_into_mp

#undef KRYPTOS_MP_ABORT_WHEN_NULL
