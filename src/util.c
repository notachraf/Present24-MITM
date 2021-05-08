#include "util.h"

/*
 * This function generates 11 subKeys from a given key
 * @param key
 * @return keys[] an array of 11 keys
 */
uint32_t* key_schedule(uint32_t key) {
    /*
     * the 80 bits register is stored in a REGISTER data structure that contains two fields,
     * one that is a 64-bit (right nibble), and the other one is a 16-bit (left nibble)
     */
    REGISTER m_key;
    /* we allocate space for 11 subKeys */
    uint32_t * keys = (uint32_t *) malloc(11 * sizeof(uint32_t));
    if(keys == NULL) {
        fprintf(stderr, "Memory allocation error : %s\n", strerror(errno));
        exit(-1);
    }
    /* the S box */
    uint8_t S_box[16] = {0xc, 0x5, 0x6, 0xb,
                         0x9, 0x0, 0xa, 0xd,
                         0x3, 0xe, 0xf, 0x8,
                         0x4, 0x7, 0x1, 0x2
    };

    /* the initial key is stored at the most significant bits of the 80-bit register */
    m_key.right_nibble = ((uint64_t) key) << 56;
    m_key.left_nibble = key >> 8;

    /* for each round we generate a new subKey */
    for (uint8_t round = 0; round < 11; ++round) {

        /* K_i = mKEY_39....mKEY16 */
        keys[round] = m_key.right_nibble >> 16 & 0xFFFFFF;

        /* temporary variables are needed to preserve data */
        uint64_t temp1 = m_key.right_nibble;
        uint16_t temp2 = m_key.left_nibble;
        /* shifting the whole key 61 bits to the left */
        m_key.left_nibble = temp1 >> 3;
        m_key.right_nibble = (temp1 << 61) | (((uint64_t) temp2) << 45) | (temp1 >> 19);

        /* the most significant 4 bits of the key goes through the SBox */
        m_key.left_nibble = (S_box[m_key.left_nibble >> 12] << 12) | (m_key.left_nibble & 0x0FFF);

        /* key bits on positions k19, k18, k17, k16 and k15 XORed with round counter */
        uint32_t xor = XOR(m_key.right_nibble >> 15 & 0x1F, round + 1);
        m_key.right_nibble = (m_key.right_nibble & 0xFFFFFFFFFFF07FFF) | (xor << 15) ;
    }
    return keys;
}


/*
 * Merge back the sorted parts of the hashtable recursively
 */
void merge_sections_of_hashtable(Hashtable* ht, Hashtable* temp,
                                 uint32_t task_per_thread, uint8_t num_threads,
                                 uint8_t aggregation) {

    uint32_t left, right, middle;

    for(uint8_t i = 0; i < num_threads; i = i + 2) {
        left = i * (task_per_thread * aggregation);
        right = ((i + 2) * task_per_thread * aggregation) - 1;
        middle = left + (task_per_thread * aggregation) - 1;
        if (right >= 0x1000000) {
            right = 0x1000000 - 1;
        }

        merge(ht, temp, left, middle, right);
    }
    if (num_threads / 2 >= 1) {
        merge_sections_of_hashtable(ht, temp, task_per_thread, num_threads / 2, aggregation * 2);
    }
}

/*
 * Merge two sorted halves of hashtable ht[from…mid] and A[mid+1…to]
 */
void merge(Hashtable* ht, Hashtable* temp, uint32_t from, uint32_t mid, uint32_t to) {
    uint32_t k = from;
    uint32_t i = from;
    uint32_t j = mid + 1;

    // loop till no elements are left in the left and right runs
    while (i <= mid && j <= to) {
        if (ht->items[i].enc < ht->items[j].enc) {
            temp->items[k].enc = ht->items[i].enc;
            temp->items[k++].key = ht->items[i++].key;
        }
        else {
            temp->items[k].enc = ht->items[j].enc;
            temp->items[k++].key = ht->items[j++].key;
        }
    }

    // copy remaining elements
    while(i <= mid) {
        temp->items[k].enc = ht->items[i].enc;
        temp->items[k++].key = ht->items[i++].key;
    }
    // copy remaining elements
    while(j <= to) {
        temp->items[k].enc = ht->items[j].enc;
        temp->items[k++].key = ht->items[j++].key;
    }


    // copy back to the original array to reflect sorted order
    for (i = from; i <= to; i++) {
        ht->items[i].enc = temp->items[i].enc;
        ht->items[i].key = temp->items[i].key;
    }
}

/*
 * Iterative merge sort function
 * @param ht        Hashtable to be sorted
 * @param size      Size of the hashtable
 */
void merge_sort(Hashtable* ht, uint32_t size) {

    uint32_t curr_size;  // For current size of sub_hashtables to be merged
                         // curr_size varies from 1 to size/2
    uint32_t left_start; // For picking starting index of left hashtable
                         // to be merged

     /* Allocate space for a temporary hashtable */
    Hashtable temp;
    temp.items = (Item *) malloc(sizeof(Item) * size);
    if(!temp.items)
        fprintf(stderr, "Memory allocation error : merge_sort: %s\n", strerror(errno));

    for (uint32_t i = 0; i < size; ++i) {
        temp.items[i].enc = ht->items[i].enc;
        temp.items[i].key = ht->items[i].key;
    }

    // Merge sub_hastables in bottom up manner.  First merge sub_hastable of
    // size 1 to create sorted sub_hastables of size 2, then merge sub_hastables
    // of size 2 to create sorted sub_hastables of size 4, and so on.
    for (curr_size = 1; curr_size <= size -1; curr_size *= 2)
    {
        // Pick starting point of different sub_hastables of current size
        for (left_start = 0; left_start < size -1; left_start += 2*curr_size)
        {
            // Find ending point of left sub_hastable. mid+1 is starting
            // point of right
            uint32_t mid = MIN(left_start + curr_size - 1, size-1);

            uint32_t right_end = MIN(left_start + 2 * curr_size - 1, size-1);

            // Merge sub_hastables ht[left_start...mid] & ht[mid+1...right_end]
            merge(ht, &temp, left_start, mid, right_end);
        }
    }
    free(temp.items);
}

/*
 * Assigns work to each thread to perform merge sort
 */
void* thread_merge_sort(void* arg) {
    Merge_sort_args* args = (Merge_sort_args *) arg;
    uint8_t th_id = args->th_id;
    uint32_t left = args->left;
    uint32_t right = args->right;
    uint32_t size = right - left;

    Hashtable sub_ht;
    sub_ht.items = (Item *) malloc(sizeof(Item) * size);

    if(sub_ht.items == NULL) {
        fprintf(stderr, "Memory allocation error : %s\n", strerror(errno));
        exit(-1);
    }
    for (uint32_t j = 0; j < size; ++j) {
        sub_ht.items[j].enc = args->ht->items[j + th_id * args->task_per_thread].enc;
        sub_ht.items[j].key = args->ht->items[j + th_id * args->task_per_thread].key;
    }
    merge_sort(&sub_ht, size);
    for (uint32_t j = 0; j < size; ++j) {
        args->ht->items[j + th_id * args->task_per_thread].enc = sub_ht.items[j].enc;
        args->ht->items[j + th_id * args->task_per_thread].key = sub_ht.items[j].key;
    }

    free(sub_ht.items);
    return NULL;
}


