#include "encryption.h"

/*
 * Encryption function PRESENT24
 * @param m             the message to be encrypted
 * @param key           the key
 * @return              Present24 cipher
 */
uint32_t PRESENT24_ENC(uint32_t m, uint32_t key) {
    uint32_t* sub_keys = key_schedule(key);

    for (uint8_t i = 0; i < 10; ++i) {
        m = XOR(m, sub_keys[i]);
        m = substitution(m);
        m = permutation(m);
    }

    m = XOR(m, sub_keys[10]);
    free(sub_keys);
    return m;
}

/*
 * Double Present24 encryption
 * This function encrypts a given message using k1
 * and then it encrypts the first cipher using a second key k2
 * @param m             the message to be encrypted
 * @param k1            First key
 * @param k2            Second key
 * @return              Double Present24 cipher
 */
uint32_t DOUBLE_PRESENT24_ENC(uint32_t m, uint32_t k1, uint32_t k2) {
    return PRESENT24_ENC(PRESENT24_ENC(m, k1), k2);
}

/*
 * Apply the S-box function for each 4bits of a given message m
 */
uint32_t substitution(uint32_t m) {
    uint8_t mask = 0xF;
    uint8_t x;

    uint8_t S_box[16] = {0xc, 0x5, 0x6, 0xb,
                         0x9, 0x0, 0xa, 0xd,
                         0x3, 0xe, 0xf, 0x8,
                         0x4, 0x7, 0x1, 0x2
    };

    for (uint8_t i = 0; i < 6; ++i) {
        x = m & mask;
        m >>= 4;
        m ^= (S_box[x] << 20);
    }
    return m;
}

/*
 * Each bit i of the message m is moved to bit position P[i]
 */
uint32_t permutation(uint32_t m) {
    uint32_t Z = 0x0;
    uint32_t bit;
    uint8_t p;

    uint8_t P[24] = {0, 6, 12, 18, 1, 7,
                 13, 19, 2, 8, 14, 20,
                 3, 9, 15, 21, 4, 10,
                 16, 22, 5, 11, 17, 23
    };

    for (uint8_t i = 0; i < 24; ++i) {
        bit = m & 0x1;
        p = P[i];
        bit <<= p;
        Z ^= bit;
        m >>= 1;
    }

    return Z;
}


