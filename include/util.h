#ifndef UTILS_H
#define UTILS_H
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <math.h>
#include <time.h>
#include <string.h>
#include <errno.h>
#include <pthread.h>

/*
 * Macro function that returns the result
 * of bitwise XOR of two arguments x and y
 */
#define XOR(x, y) (x ^ y);

/*
 * Macro function that returns min(x, y)
 */
#define MIN(a,b) (((a)<(b))?(a):(b))


/* 80-bits register */
typedef struct {
    uint64_t right_nibble;
    uint16_t left_nibble;
} REGISTER;

/*
 * This structure represents one item of the hashtable
 * which contains a cipher and the key used to obtain it
 */
typedef struct {
    uint32_t enc;    /* 24-bit encrypted text */
    uint32_t key;    /* 24-bit encryption key */
} Item;

/* Hashtable of encrypted texts mapped to all possible keys */
typedef struct {
    Item* items;
} Hashtable;

/*
 * This structure containing the information needed
 * by the encryption threads
 */
typedef struct {
    Hashtable*  ht;                     /* The encryption hashtable */
    uint32_t    m;                      /* The message to be encrypted */
    uint32_t    start;                  /* Starting index  */
    uint32_t    stop;                   /* Last index  */
} Generate_encryption_hashtable_args;

/*
 * This structure containing the information needed
 * by the decryption threads
 */
typedef struct {
    Hashtable*  ht;                     /* The decryption hashtable */
    uint32_t    c;                      /* The cipher to be decrypted */
    uint32_t    start;                  /* Starting index */
    uint32_t    stop;                   /* Last index */
} Generate_decryption_hashtable_args;

/*
 * This structure containing the information needed
 * by the sorting threads
 */
typedef struct {
    Hashtable*  ht;                     /* The hashtable to be sorted */
    uint8_t     th_id;                  /* Thread ID */
    uint8_t     num_threads;            /* Number of threads */
    uint32_t    task_per_thread;        /* Task per thread */
    uint32_t    left;                   /* Starting index */
    uint32_t    right;                  /* Last index */
} Merge_sort_args;

/*
 * This structure containing the information needed
 * to find collisions between two hash tables
 */
typedef struct {
    Hashtable*  ht1;                    /* First Hashtable */
    Hashtable*  ht2;                    /* Second Hashtable */
    uint32_t    m2;                     /* Second message */
    uint32_t    c2;                     /* Second  cipher*/
    uint32_t    start;                  /* Starting index */
    uint32_t    stop;                   /* Last index */
    uint32_t    collisions;             /* Number of collisions per thread */
} Collisions_args;

/* Prototypes */
uint32_t* key_schedule(uint32_t key);
void *thread_merge_sort(void* args);
void merge_sort(Hashtable* ht, uint32_t size);
void merge(Hashtable* ht, Hashtable* temp, uint32_t from, uint32_t mid, uint32_t to);
void merge_sections_of_hashtable(Hashtable* ht, Hashtable* temp, uint32_t task_per_thread, uint8_t num_threads, uint8_t aggregation);

#endif //UTILS_H
