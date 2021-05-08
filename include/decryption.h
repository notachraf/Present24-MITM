#ifndef DECRYPTION_H
#define DECRYPTION_H
#include "util.h"

/* Prototypes */
uint32_t PRESENT24_DEC(uint32_t c, uint32_t key);
uint32_t substitution_inv(uint32_t m);
uint32_t permutation_inv(uint32_t m);

#endif //DECRYPTION_H
