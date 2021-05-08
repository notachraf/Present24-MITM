#ifndef ENCRYPTION_H
#define ENCRYPTION_H
#include "util.h"

/* Prototypes */
uint32_t PRESENT24_ENC(uint32_t m, uint32_t key);
uint32_t DOUBLE_PRESENT24_ENC(uint32_t m, uint32_t k1, uint32_t k2);
uint32_t substitution(uint32_t m);
uint32_t permutation(uint32_t m);

#endif //ENCRYPTION_H
