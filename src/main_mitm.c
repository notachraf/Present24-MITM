#include <stdio.h>
#include <stdint.h>
#include "mitm.h"


int main(int argc, char** argv) {

    if(argc == 6){
        
        uint32_t m1 = (uint32_t) strtol(argv[1], NULL, 16);
        uint32_t c1 = (uint32_t) strtol(argv[2], NULL, 16);
        uint32_t m2 = (uint32_t) strtol(argv[3], NULL, 16);
        uint32_t c2 = (uint32_t) strtol(argv[4], NULL, 16);
        uint8_t num_threads = (uint32_t) strtol(argv[5], NULL, 10);        

        #ifdef _WIN32
            clock_t t = clock();
            mitm(m1, c1, m2, c2, num_threads);
            double elapsed = (clock()-t)/(double)CLOCKS_PER_SEC;
        #else
            struct timespec start, finish;
            clock_gettime(CLOCK_MONOTONIC, &start);
            mitm(m1, c1, m2, c2, num_threads);
            clock_gettime(CLOCK_MONOTONIC, &finish);
            double elapsed = (finish.tv_sec - start.tv_sec);
            elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
        #endif

        printf("MITM attack performed in %.3f sec\n", elapsed);
    }
    else {
        fprintf(stderr, "Usage: \n\t%s [m1 m2 c1 c2] [number_of_threads]\n", argv[0]);
        exit(-1);
    }

    return 0;

}
