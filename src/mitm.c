#include "mitm.h"

/*
 * Generate the encryption hashtable for a given thread
 */
void* generate_encryption_hashtable(void* arg) {
    Generate_encryption_hashtable_args* args = (Generate_encryption_hashtable_args *) arg;
    for (uint32_t i = args->start; i < args->stop; ++i) {
        args->ht->items[i].key = i;
        args->ht->items[i].enc = PRESENT24_ENC(args->m, i);
    }
    return NULL;
}

/*
 * Generate the decryption hashtable for a given thread
 */
void* generate_decryption_hashtable(void* arg) {
    Generate_decryption_hashtable_args* args = (Generate_decryption_hashtable_args *) arg;
    for (uint32_t i = args->start; i < args->stop; ++i) {
        args->ht->items[i].key = i;
        args->ht->items[i].enc = PRESENT24_DEC(args->c, i);
    }
    return NULL;
}

/*
 * Find collisions between two hashtables
 * And for each collision test if (k1, k2)
 * are a valid key for the second pair (plaintext, cipher)
 */
void* find_collisions(void* arg) {
    Collisions_args* args = (Collisions_args *) arg;

    uint32_t i = args->start;
    uint32_t j = args->start;
    Hashtable* ht1 = args->ht1;
    Hashtable* ht2 = args->ht2;
    uint32_t m2 = args->m2;
    uint32_t c2 = args->c2;
    uint32_t temp;

    while( (i < args->stop || j < args->stop) &&
           (i < 0x1000000  && j < 0x1000000 )) {

        if(ht1->items[i].enc < ht2->items[j].enc) {
            i++;
        }
        else if(ht1->items[i].enc > ht2->items[j].enc) {
            j++;
        }
        else {  /* if(ht1.items[i].enc == ht2.items[j].enc) */
            temp = ht1->items[i].enc;
            args->collisions++;
            while(ht1->items[i].enc == temp) {
                while(ht2->items[j].enc == temp) {
                    if(c2 == DOUBLE_PRESENT24_ENC(m2, ht1->items[i].key, ht2->items[j].key)) {
                        printf("\n\t(k1, k2) = (%x, %x)", ht1->items[i].key, ht2->items[j].key);
                    }
                    j++;
                }
                i++;
            }
        }
    }
    return NULL;
}

/*
 * Check if a hasahtable is sorted
 */
void check_if_ht_is_sorted(Hashtable* ht) {
    for (uint32_t l = 0; l < 0x1000000-1; ++l) {
        if(ht->items[l].enc > ht->items[l+1].enc) {
            fprintf(stdout, "ht is not sorted\n");
            fprintf(stdout, "i=%x : %x > %x\n", l, ht->items[l].enc, ht->items[l+1].enc);
            exit(0);
        }
    }
        fprintf(stderr, "\tht is sorted\n");
}

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
void mitm(uint32_t m1, uint32_t c1, uint32_t m2, uint32_t c2, uint8_t num_threads) {
    /*
     * Used to get the duration of the different
     * stages of the attack.
     */
    struct timespec start, finish;
    double elapsed;
    clock_t t;

    /*
     * This has the effect of rounding up the number of tasks
     * per thread, which is useful in case 2^24 does not divide
     * evenly by number_thread.
     */
    uint32_t task_per_thread = 0x1000000 / num_threads;
    uint32_t offset = 0x1000000 % num_threads;

    /*
     * ht1 contains every possible key mapped to it's cipher
     * ht2 contains every possible key mapped to it's decipher
     */
    Hashtable ht1, ht2;
    /*
     * Memory allocation
     */
    ht1.items = (Item *) malloc(sizeof(Item) * 0x1000000);
    ht2.items = (Item *) malloc(sizeof(Item) * 0x1000000);
    if(ht1.items == NULL || ht2.items == NULL )
        fprintf(stderr, "Memory allocation error : %s\n", strerror(errno));

    /*
     * Memory allocation for threads
     */
    pthread_t* enc_threads = (pthread_t *) malloc(sizeof(pthread_t) * num_threads);
    pthread_t* dec_threads = (pthread_t *) malloc(sizeof(pthread_t) * num_threads);
    pthread_t* sorting_threads = (pthread_t *) malloc(sizeof(pthread_t) * num_threads);
    pthread_t* collision_threads = (pthread_t *) malloc(sizeof(pthread_t) * num_threads);
    if(enc_threads == NULL || dec_threads == NULL || sorting_threads == NULL || collision_threads == NULL)
        fprintf(stderr, "Memory allocation error : %s\n", strerror(errno));

    /*
     * Each array contains the argument for its corresponding thread
     */
    Generate_encryption_hashtable_args args_enc[num_threads];
    Generate_decryption_hashtable_args args_dec[num_threads];
    Merge_sort_args args_merge_sort[num_threads];
    Collisions_args args_collision[num_threads];

    /*
     * Initialise number of collisions by 0
     */
    uint32_t collisions = 0;


    printf("Starting MITM attack with %d thread", num_threads);
    if(num_threads > 1)
        printf("s");
    printf("..\n\n");
    printf("\tMessage 1: %x  |  Cipher 1: %x\n", m1, c1);
    printf("\tMessage 2: %x  |  Cipher 2: %x\n\n", m2, c2);



#ifdef _WIN32
     t = clock();
#else
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif

    printf("%-45s", "Generating the encryption hash-table..");
    /*
     * Multi-threaded encryption
     */
    uint32_t rc;
    for (uint8_t j = 0; j < num_threads; ++j) {
        args_enc[j].ht = &ht1;
        args_enc[j].m = m1;
        args_enc[j].start = j * task_per_thread;
        args_enc[j].stop = (j + 1) * task_per_thread;
        if(j == num_threads - 1)
            args_enc[j].stop += offset;

        // Launch threads
        rc = pthread_create(&enc_threads[j], NULL, generate_encryption_hashtable, &args_enc[j]);
        if (rc){
            fprintf(stderr, "ERROR; return code from pthread_create() is %d\n", rc);
            exit(-1);
        }
    }
    // Wait for threads to finish
    for (uint8_t  k = 0; k < num_threads; ++k) {
        pthread_join(enc_threads[k], NULL);
    }

#ifdef _WIN32
    elapsed = (clock()-t)/(double)CLOCKS_PER_SEC;
#else
    clock_gettime(CLOCK_MONOTONIC, &finish);
    elapsed = (finish.tv_sec - start.tv_sec);
    elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
#endif
    printf("✓ Done in %.3f sec\n", elapsed);




#ifdef _WIN32
    t = clock();
#else
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif

    printf("%-45s", "Generating the decryption hash-table..");
    /*
     * Multi-threaded decryption
     */
    for (uint8_t j = 0; j < num_threads; ++j) {
        args_dec[j].ht = &ht2;
        args_dec[j].c = c1;
        args_dec[j].start = j * task_per_thread;
        args_dec[j].stop = (j + 1) * task_per_thread;
        if(j == num_threads - 1)
            args_dec[j].stop += offset;
        // Launch threads
        rc = pthread_create(&dec_threads[j], NULL, generate_decryption_hashtable, &args_dec[j]);
        if (rc){
            fprintf(stderr, "ERROR; return code from pthread_create() is %d\n", rc);
            exit(-1);
        }
    }
    // Wait for threads to finish
    for (uint8_t k = 0; k < num_threads; ++k) {
        pthread_join(dec_threads[k], NULL);
    }

#ifdef _WIN32
    elapsed = (clock()-t)/(double)CLOCKS_PER_SEC;
#else
    clock_gettime(CLOCK_MONOTONIC, &finish);
    elapsed = (finish.tv_sec - start.tv_sec);
    elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
#endif
    printf("✓ Done in %.3f sec\n", elapsed);




#ifdef _WIN32
    t = clock();
#else
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif

    printf("%-45s", "Sorting the encryption hash-table..");
    /**
     * Sorting the encryption hash-table
     */
    for (uint32_t j = 0; j < num_threads; ++j) {
        args_merge_sort[j].ht = &ht1;
        args_merge_sort[j].th_id = j;
        args_merge_sort[j].left = j * task_per_thread;
        args_merge_sort[j].right = (j + 1) * task_per_thread;
        args_merge_sort[j].num_threads = num_threads;
        args_merge_sort[j].task_per_thread = task_per_thread;
        if(j == num_threads - 1)
            args_merge_sort[j].right += offset;
        // Launch threads
        rc = pthread_create(&sorting_threads[j], NULL, thread_merge_sort, &args_merge_sort[j]);
        if (rc){
            fprintf(stderr, "ERROR; return code from pthread_create() is %d\n", rc);
            exit(-1);
        }
    }
    // Wait for threads to finish
    for (uint8_t k = 0; k < num_threads; ++k) {
        pthread_join(sorting_threads[k], NULL);
    }

    /*
     * Merge sort requires o(n) space
     * so we have to allocate space for a temporary Hashtable
     */
    Hashtable temp;
    temp.items = (Item *) malloc(sizeof(Item) * 0x1000000);
    if(!temp.items)
        fprintf(stderr, "Memory allocation error : merge_sort: %s\n", strerror(errno));

    for (uint32_t i = 0; i < 0x1000000; ++i) {
        temp.items[i].enc = ht1.items[i].enc;
        temp.items[i].key = ht1.items[i].key;
    }
    merge_sections_of_hashtable(&ht1, &temp, task_per_thread, num_threads, 1);

#ifdef _WIN32
    elapsed = (clock()-t)/(double)CLOCKS_PER_SEC;
#else
    clock_gettime(CLOCK_MONOTONIC, &finish);
    elapsed = (finish.tv_sec - start.tv_sec);
    elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
#endif
    printf("✓ Done in %.3f sec\n", elapsed);




#ifdef _WIN32
    t = clock();
#else
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif

    printf("%-45s", "Sorting the decryption hash-table..");
    /**
     * Sorting the decryption hash-table
     */
    for (uint32_t j = 0; j < num_threads; ++j) {
        args_merge_sort[j].ht = &ht2;
        args_merge_sort[j].th_id = j;
        args_merge_sort[j].left = j * task_per_thread;
        args_merge_sort[j].right = (j + 1) * task_per_thread;
        args_merge_sort[j].num_threads = num_threads;
        args_merge_sort[j].task_per_thread = task_per_thread;
        /* the last thread must not go past 2^24  */
        if(j == num_threads - 1)
            args_merge_sort[j].right += offset;
//            args_merge_sort[j].right = 0x1000000;
        // Launch threads
        rc = pthread_create(&sorting_threads[j], NULL, thread_merge_sort, &args_merge_sort[j]);
        if (rc){
            fprintf(stderr, "ERROR; return code from pthread_create() is %d\n", rc);
            exit(-1);
        }

    }
    // Wait for threads to finish
    for (uint8_t k = 0; k < num_threads; ++k) {
        pthread_join(sorting_threads[k], NULL);
    }

    for (uint32_t i = 0; i < 0x1000000; ++i) {
        temp.items[i].enc = ht2.items[i].enc;
        temp.items[i].key = ht2.items[i].key;
    }
    merge_sections_of_hashtable(&ht2, &temp, task_per_thread, num_threads, 1);

#ifdef _WIN32
    elapsed = (clock()-t)/(double)CLOCKS_PER_SEC;
#else
    clock_gettime(CLOCK_MONOTONIC, &finish);
    elapsed = (finish.tv_sec - start.tv_sec);
    elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
#endif
    printf("✓ Done in %.3f sec\n", elapsed);



#ifdef _WIN32
    t = clock();
#else
    clock_gettime(CLOCK_MONOTONIC, &start);
#endif

    /**
     * Looking for a valid key pair
     */
    printf("%-45s", "\nLooking for a valid key pair..");

    for (uint8_t j = 0; j < num_threads; ++j) {
        args_collision[j].ht1 = &ht1;
        args_collision[j].ht2 = &ht2;
        args_collision[j].m2 = m2;
        args_collision[j].c2 = c2;
        args_collision[j].start = j * task_per_thread;
        args_collision[j].stop = (j + 1) * task_per_thread;
        args_collision[j].collisions = 0;
        if(j == num_threads - 1)
            args_collision[j].stop += offset;

        // Launch threads
        rc = pthread_create(&collision_threads[j], NULL, find_collisions, &args_collision[j]);
        if (rc){
            fprintf(stderr, "ERROR; return code from pthread_create() is %d : %s\n", rc, strerror(rc));
            exit(-1);
        }
    }

    // Wait for threads to finish
    for (uint8_t k = 0; k < num_threads; ++k) {
        pthread_join(collision_threads[k], NULL);
        collisions += args_collision[k].collisions;
    }


#ifdef _WIN32
    elapsed = (clock()-t)/(double)CLOCKS_PER_SEC;
#else
    clock_gettime(CLOCK_MONOTONIC, &finish);
    elapsed = (finish.tv_sec - start.tv_sec);
    elapsed += (finish.tv_nsec - start.tv_nsec) / 1000000000.0;
#endif
    printf("\n%-45s✓ Found %d collisions in %.3f sec\n", "", collisions, elapsed);


    /*
     * Free allocated memory
     */
    free(enc_threads);
    free(dec_threads);
    free(sorting_threads);
    free(collision_threads);
    free(ht1.items);
    free(ht2.items);
    free(temp.items);
}

