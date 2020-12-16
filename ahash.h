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

typedef struct ahasher_s {
    uint64_t buffer;
    uint64_t pad;
    uint64_t extra_keys[2];
} ahasher_t;
#endif

#endif //AHASH_AHASH_H
