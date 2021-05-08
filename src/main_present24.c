#include <stdio.h>
#include "stdint.h"
#include "encryption.h"
#include "decryption.h"


int main() {

    /*
     * Print a random message along with its cipher and decipher using a key k
     */

    printf("%-6s  |   %-6s   |   %-6s   |  %-6s\n", "message", "key", "cipher", "decipher");

    uint32_t m = 0x7e6359;
    uint32_t k = 0xce46c4;
    uint32_t c = PRESENT24_ENC(m, k);
    uint32_t d = PRESENT24_DEC(c, k);
    printf("%06x   |   ", m);
    printf("%06x   |   ", k);
    printf("%06x   |   ", c);
    printf("%06x\n", d);

    m = 0xc1ef39;
    k = 0x0;
    c = PRESENT24_ENC(m, k);
    d = PRESENT24_DEC(c, k);
    printf("%06x   |   ", m);
    printf("%06x   |   ", k);
    printf("%06x   |   ", c);
    printf("%06x\n", d);


    m = 0xffffff;
    k = 0x0;
    c = PRESENT24_ENC(m, k);
    d = PRESENT24_DEC(c, k);
    printf("%06x   |   ", m);
    printf("%06x   |   ", k);
    printf("%06x   |   ", c);
    printf("%06x\n", d);

    m = 0x0;
    k = 0xffffff;
    c = PRESENT24_ENC(m, k);
    d = PRESENT24_DEC(c, k);
    printf("%06x   |   ", m);
    printf("%06x   |   ", k);
    printf("%06x   |   ", c);
    printf("%06x\n", d);


    m = 0xf955b9;
    k = 0xd1bd2d;
    c = PRESENT24_ENC(m, k);
    d = PRESENT24_DEC(c, k);
    printf("%06x   |   ", m);
    printf("%06x   |   ", k);
    printf("%06x   |   ", c);
    printf("%06x\n", d);

    return 0;
}