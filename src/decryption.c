#include "decryption.h"

/*
 * Decryption function PRESENT24
 * @param m             the message to be decrypted
 * @param key           the key
 * @return              Present24 decipher
 */
uint32_t PRESENT24_DEC(uint32_t c, uint32_t key) {
    uint32_t* sub_keys = key_schedule(key);

    c = XOR(c, sub_keys[10]);

    for (uint8_t i = 0; i < 10; ++i) {
        c = permutation_inv(c);
        c = substitution_inv(c);
        c = XOR(c, sub_keys[9 - i]);
    }

    free(sub_keys);
    return c;
}

/*
 * Apply the inverse of the S-box function for each 4bits of a given message m
 */
uint32_t substitution_inv(uint32_t m) {
    uint8_t mask = 0x0F;

    uint8_t S_box_inv[16] = {0x5, 0xe, 0xf, 0x8,
                     0xc, 0x1, 0x2, 0xd,
                     0xb, 0x4, 0x6, 0x3,
                     0x0, 0x7, 0x9, 0xa
    };

    for (uint8_t i = 0; i < 6; ++i) {
        uint8_t x = m & mask;
        m >>= 4;
        m ^= (S_box_inv[x] << 20);
    }
    return m;
}

/*
 * Each bit i of the message m is moved to bit position P_inv[i]
 */
uint32_t permutation_inv(uint32_t m) {
    uint32_t Z = 0x0;
    uint32_t bit;
    uint8_t p;

    uint8_t P_inv[24] = {0, 4, 8, 12, 16, 20,
                         1, 5, 9, 13, 17, 21,
                         2, 6, 10, 14, 18, 22,
                         3, 7, 11, 15, 19, 23
    };


    for (uint8_t i = 0; i < 24; ++i) {
        bit = m & 0x1;
        p = P_inv[i];
        bit <<= p;
        Z ^= bit;
        m >>= 1;
    }
    return Z;
}