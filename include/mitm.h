#ifndef MITM_H
#define MITM_H

#include "util.h"
#include "encryption.h"
#include "decryption.h"

/*
 * This function performs the Meet in the middle attack on 2Present24
 * Using two known pairs of (plaintext, cipher)
 *
 * @param m1            Message 1
 * @param c1            Cipher 1
 * @param m2            Message 2
 * @param c2            Cipher 2
 * @param num_threads   Number of threads
 */
void mitm(uint32_t m1, uint32_t c1, uint32_t m2, uint32_t c2, uint8_t num_threads);

#endif //MITM_H
