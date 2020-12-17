//
// Created by schrodinger on 12/16/20.
//
#include "random_state.h"
#include "ahash.h"
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include <string.h>

atomic_size_t COUNTER = 0;

random_state_t new_state_from_keys(uint64_t *a, uint64_t *b) {
    ahasher_t hasher = hasher_from_random_state( a[0], a[1], a[2], a[3] );
    uint64_t stack_position = (uint64_t)(&new_state_from_keys);
#if defined(__arm__) || defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM) || defined(_M_ARM64)
    uint64_t counter = (uint64_t)atomic_load_explicit(&COUNTER, memory_order_relaxed);
    counter += stack_position;
    atomic_store_explicit(&COUNTER, counter, memory_order_relaxed);
#else
    uint64_t counter = (uint64_t)atomic_fetch_add_explicit(&COUNTER, stack_position, memory_order_relaxed);
#endif
    hasher = write_uint64_t(hasher, counter);
    random_state_t result;
    result.keys[0] =  finish(write_uint64_t(hasher, b[0]));
    result.keys[1] =  finish(write_uint64_t(hasher, b[1]));
    result.keys[2] =  finish(write_uint64_t(hasher, b[2]));
    result.keys[3] =  finish(write_uint64_t(hasher, b[3]));
    return result;
}

random_state_t new_state() {
    return new_state_from_keys(PI, PI2);
}

