//
// Created by schrodinger on 12/16/20.
//
#include "random_state.h"

#include "ahash.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

random_state_t new_state_from_keys(uint64_t* a, uint64_t* b)
{
  static atomic_size_t COUNTER = 0;
  ahasher_t hasher = hasher_from_random_state(a[0], a[1], a[2], a[3]);
  uint64_t stack_position = (ptrdiff_t)(&new_state_from_keys);
#if defined(__arm__) || defined(__arm64__) || defined(__aarch64__) || \
  defined(_M_ARM) || defined(_M_ARM64)
  uint64_t counter =
    (uint64_t)atomic_load_explicit(&COUNTER, memory_order_relaxed);
  counter += stack_position;
  atomic_store_explicit(&COUNTER, counter, memory_order_relaxed);
#else
  uint64_t counter = (uint64_t)atomic_fetch_add_explicit(
    &COUNTER, stack_position, memory_order_relaxed);
#endif
  hasher = write_uint64_t(hasher, counter);
  random_state_t result;
  result.keys[0] = finish(write_uint64_t(hasher, b[0]));
  result.keys[1] = finish(write_uint64_t(hasher, b[1]));
  result.keys[2] = finish(write_uint64_t(hasher, b[2]));
  result.keys[3] = finish(write_uint64_t(hasher, b[3]));
  return result;
}

uint64_t PI[4] = {
  0x243f6a8885a308d3ull,
  0x13198a2e03707344ull,
  0xa4093822299f31d0ull,
  0x082efa98ec4e6c89ull,
};

uint64_t PI2[4] = {
  0x452821e638d01377ull,
  0xbe5466cf34e90c6cull,
  0xc0ac29b7c97c50ddull,
  0x3f84d5b5b5470917ull,
};

random_state_t new_state()
{
  return new_state_from_keys(PI, PI2);
}

void reinitialize_global_seed(uint64_t a, uint64_t b, uint64_t c, uint64_t d)
{
  PI2[0] = a;
  PI2[1] = b;
  PI2[2] = c;
  PI2[3] = d;
}
