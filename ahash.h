#ifndef AHASH_AHASH_H
#define AHASH_AHASH_H
#include "definitions.h"

#ifndef USE_FALLBACK
typedef struct ahasher_s {
    aes128_t enc;
    aes128_t sum;
    aes128_t key;
} ahasher_t;
#else
#include <string.h>
#if defined(__SSE2__)
#define TARGET_HAS_128BIT
#define LOAD128(x) (_mm_loadu_si128((vec128_t *)(x)))
#define XOR128(x, y) (_mm_xor_si128((x), (y)))
#include <emmintrin.h>
typedef __m128i vec128_t;
#elif defined(__ARM_NEON)
#if !defined(_MSC_VER) || !defined(_M_ARM64)
#include <arm_neon.h>
#else
#include <arm64_neon.h>
#endif
#define TARGET_HAS_128BIT
#define LOAD128(x) ((vec128_t)vld1q_u64((uint64_t *)(x)))
#define XOR128(x, y) ((vec128_t)veorq_u64((x), (y)))
typedef uint64x2_t vec128_t;
#endif

#define MULTIPLIER 6364136223846793005ull
#define ROT        23
typedef struct ahasher_s {
    uint64_t buffer;
    uint64_t pad;
#ifdef TARGET_HAS_128BIT
    vec128_t extra_keys;
#else
    uint64_t extra_keys[2];
#endif
} ahasher_t;
#endif


ahasher_t hasher_from_random_state(uint64_t k0, uint64_t k1, uint64_t k2, uint64_t k3);

#define WRITE_API(TYPE)                                                         \
  ahasher_t write_##TYPE(ahasher_t hasher, TYPE value);

WRITE_API(uint64_t);
WRITE_API(int64_t);
WRITE_API(uint32_t);
WRITE_API(int32_t);
WRITE_API(uint16_t);
WRITE_API(int16_t);
WRITE_API(uint8_t);
WRITE_API(int8_t);

ahasher_t add_length(ahasher_t hasher, size_t length);
ahasher_t hash_write(ahasher_t hasher, const void *__restrict__ input, size_t size);
uint64_t finish(ahasher_t hasher);
uint64_t ahash64(const void* __restrict__ buf, size_t size, uint64_t seed);
const char * ahash_version( void );
#endif //AHASH_AHASH_H
