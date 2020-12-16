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


extern atomic_size_t COUNTER;

#endif //AHASH_RANDOM_STATE_H
