//
// Created by schrodinger on 12/16/20.
//

#ifndef AHASH_RANDOM_STATE_H
#define AHASH_RANDOM_STATE_H

#include <stdint.h>
#include <stdatomic.h>

typedef struct random_state_s {
    uint64_t keys[4];
} random_state_t;


static uint64_t PI[4] = {
        0x243f6a8885a308d3ull,
        0x13198a2e03707344ull,
        0xa4093822299f31d0ull,
        0x082efa98ec4e6c89ull,
};


static uint64_t PI2[4] = {
        0x452821e638d01377ull,
        0xbe5466cf34e90c6cull,
        0xc0ac29b7c97c50ddull,
        0x3f84d5b5b5470917ull,
};



extern atomic_size_t COUNTER;
random_state_t new_state();
random_state_t new_state_from_keys(uint64_t *a, uint64_t *b);
#define CREATE_HASHER(state) \
     hasher_from_random_state(state.keys[0], state.keys[1], state.keys[2], state.keys[3])
#endif //AHASH_RANDOM_STATE_H
