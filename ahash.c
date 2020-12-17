#include "ahash.h"
#include "random_state.h"
#include <stddef.h>
#ifndef USE_FALLBACK

ahasher_t new_with_key(aes128_t key1, aes128_t key2) {
  ahasher_t result;
  result.enc = key1;
  result.sum = key2;
  result.key = AES_OR(key1, key2);
  return result;
}

ahasher_t hasher_from_random_state(uint64_t k0, uint64_t k1, uint64_t k2, uint64_t k3) {
  aes128_t key1, key2;
#ifdef x86_TARGET
  key1 = _mm_set_epi64x(k1, k0);
  key2 = _mm_set_epi64x(k3, k2);
#else
  uint64_t keys[4] = {k0, k1, k2, k3};
  key1 = (aes128_t)vld1q_u64(keys);
  key2 = (aes128_t)vld1q_u64(keys + 2);
#endif
  return new_with_key(key1, key2);
}

static FAST_PATH aes128_t add_low(aes128_t a, uint64_t b) {
#ifdef x86_TARGET
  aes128_t temp = _mm_set_epi64x(0, b);
  return _mm_add_epi64(a, temp);
#else
  uint64_t temp[2] = {b, 0};
  uint64x2_t operand = vld1q_u64(temp);
  return (aes128_t)vaddq_u64((uint64x2_t)a, operand);
#endif
}

static FAST_PATH aes128_t add_high(aes128_t a, uint64_t b) {
#ifdef x86_TARGET
  aes128_t temp = _mm_set_epi64x(b, 0);
  return _mm_add_epi64(a, temp);
#else
  uint64_t temp[2] = {0, b};
  uint64x2_t operand = vld1q_u64(temp);
  return (aes128_t)vaddq_u64((uint64x2_t)a, operand);
#endif
}

ahasher_t add_length(ahasher_t hasher, size_t length) {
  hasher.enc = add_low(hasher.enc, length);
  return hasher;
}

ahasher_t hash1(ahasher_t hasher, aes128_t v1) {
  hasher.enc = aes_encode(hasher.enc, v1);
  hasher.sum = shuffle_add(hasher.sum, v1);
  return hasher;
}

ahasher_t hash2(ahasher_t hasher, aes128_t v1, aes128_t v2) {
  hasher.enc = aes_encode(hasher.enc, v1);
  hasher.sum = shuffle_add(hasher.sum, v1);
  hasher.enc = aes_encode(hasher.enc, v2);
  hasher.sum = shuffle_add(hasher.sum, v2);
  return hasher;
}

ahasher_t write_uint64_t(ahasher_t hasher, uint64_t value) {
#ifdef x86_TARGET
  aes128_t temp = _mm_set_epi64x(value, 0);
  return hash1(hasher, temp);
#else
  uint64_t temp[2] = {0, value};
  aes128_t key = (aes128_t)vld1q_u64(temp);
  return hash1(hasher, key);
#endif
}

#define WRITABLE(TYPE)                                                         \
  ahasher_t write_##TYPE(ahasher_t hasher, TYPE value) {                       \
    return write_uint64_t(hasher, (uint64_t)value);                            \
  }

WRITABLE(uint8_t)
WRITABLE(int8_t)
WRITABLE(uint16_t)
WRITABLE(int16_t)
WRITABLE(uint32_t)
WRITABLE(int32_t)
WRITABLE(int64_t)

ahasher_t hash_write(ahasher_t hasher, const void *__restrict__ input, size_t size) {
  hasher = add_length(hasher, size);
  if (size < 8) {
    uint64_t data[2];
    if (size >= 2) {
      if (size >= 4) {
        data[0] = *(uint32_t *)input;
        data[1] = *(uint32_t *)((uint8_t *)input + size - sizeof(uint32_t));
      } else {
        data[0] = *(uint16_t *)input;  /// TODO: aarch64 should be good with unaligned access
        data[1] = *((uint8_t *)input + size - 1);
      }
    } else {
      if (size > 0) {
        data[0] = *((uint8_t *)input);
        data[1] = 0;
      } else {
        data[1] = data[0] = 0;
      }
    }
#ifdef x86_TARGET
    aes128_t temp = _mm_set_epi64x(data[1], data[0]);
#else
    aes128_t temp = (aes128_t)vld1q_u64(data);
#endif
    return hash1(hasher, temp);
  } else {
    if (size > 32) {
      if (size > 64) {
#if !(defined(__VAES__) && defined(x86_TARGET))
        aes128_t tail[4];
        aes128_t current[4];
        aes128_t sum[2];
#if defined(x86_TARGET)
        tail[0] = /// TODO: whether _mm_lddqu_si128 is good enough here for unaligned access
            _mm_lddqu_si128((aes128_t *)(input + size - 4 * sizeof(aes128_t)));
        tail[1] =
            _mm_lddqu_si128((aes128_t *)(input + size - 3 * sizeof(aes128_t)));
        tail[2] =
            _mm_lddqu_si128((aes128_t *)(input + size - 2 * sizeof(aes128_t)));
        tail[3] =
            _mm_lddqu_si128((aes128_t *)(input + size - 1 * sizeof(aes128_t)));
#else
        tail[0] = (aes128_t)vld1q_u8(
            (uint8_t *)(input + size - 4 * sizeof(aes128_t)));
        tail[1] = (aes128_t)vld1q_u8(
            (uint8_t *)(input + size - 3 * sizeof(aes128_t)));
        tail[2] = (aes128_t)vld1q_u8(
            (uint8_t *)(input + size - 2 * sizeof(aes128_t)));
        tail[3] = (aes128_t)vld1q_u8(
            (uint8_t *)(input + size - 1 * sizeof(aes128_t)));
#endif
        current[0] = aes_encode(hasher.key, tail[0]);
        current[1] = aes_encode(hasher.key, tail[1]);
        current[2] = aes_encode(hasher.key, tail[2]);
        current[3] = aes_encode(hasher.key, tail[3]);
        sum[0] = add_by_64s(hasher.key, tail[0]);
        sum[1] = add_by_64s(hasher.key, tail[1]);
        sum[0] = shuffle_add(sum[0], tail[2]);
        sum[1] = shuffle_add(sum[1], tail[3]);
        while (size > 64) {
#ifdef x86_TARGET
          tail[0] = _mm_lddqu_si128((aes128_t *)(input + 0 * sizeof(aes128_t)));
          tail[1] = _mm_lddqu_si128((aes128_t *)(input + 1 * sizeof(aes128_t)));
          tail[2] = _mm_lddqu_si128((aes128_t *)(input + 2 * sizeof(aes128_t)));
          tail[3] = _mm_lddqu_si128((aes128_t *)(input + 3 * sizeof(aes128_t)));
#else
          tail[0] =
              (aes128_t)vld1q_u8((uint8_t *)(input + 0 * sizeof(aes128_t)));
          tail[1] =
              (aes128_t)vld1q_u8((uint8_t *)(input + 1 * sizeof(aes128_t)));
          tail[2] =
              (aes128_t)vld1q_u8((uint8_t *)(input + 2 * sizeof(aes128_t)));
          tail[3] =
              (aes128_t)vld1q_u8((uint8_t *)(input + 3 * sizeof(aes128_t)));
#endif
          current[0] = aes_encode(current[0], tail[0]);
          current[1] = aes_encode(current[1], tail[1]);
          current[2] = aes_encode(current[2], tail[2]);
          current[3] = aes_encode(current[3], tail[3]);
          sum[0] = shuffle_add(sum[0], tail[0]);
          sum[1] = shuffle_add(sum[1], tail[1]);
          sum[0] = shuffle_add(sum[0], tail[2]);
          sum[1] = shuffle_add(sum[1], tail[3]);
          size -= 64;
          input = ((uint8_t *)input) + 64;
        }
        hasher = hash2(hasher, aes_encode(current[0], current[1]),
                       aes_encode(current[2], current[3]));
        return hash1(hasher, add_by_64s(sum[0], sum[1]));
      } else {
        aes128_t head[2], tail[2];
#ifdef x86_TARGET
        head[0] = _mm_lddqu_si128((aes128_t *)(input + 0 * sizeof(aes128_t)));
        head[1] = _mm_lddqu_si128((aes128_t *)(input + 1 * sizeof(aes128_t)));
        tail[0] =
            _mm_lddqu_si128((aes128_t *)(input + size - 2 * sizeof(aes128_t)));
        tail[1] =
            _mm_lddqu_si128((aes128_t *)(input + size - 1 * sizeof(aes128_t)));
#else
        head[0] = (aes128_t)vld1q_u8((uint8_t *)(input + 0 * sizeof(aes128_t)));
        head[1] = (aes128_t)vld1q_u8((uint8_t *)(input + 1 * sizeof(aes128_t)));
        tail[0] = (aes128_t)vld1q_u8(
            (uint8_t *)(input + size - 2 * sizeof(aes128_t)));
        tail[1] = (aes128_t)vld1q_u8(
            (uint8_t *)(input + size - 1 * sizeof(aes128_t)));
#endif
        hasher = hash2(hasher, head[0], head[1]);
        return hash2(hasher, tail[0], tail[1]);
#else // x86_64 VAES intruction set
#ifdef __AVX512DQ__
          if (size > 128) {
              aes512_t tail[2];
              aes512_t current[2];
              aes512_t sum;
              tail[0] =
                      _mm512_loadu_si512((aes512_t *) (input + size - 2 * sizeof(aes512_t)));
              tail[1] =
                      _mm512_loadu_si512((aes512_t *) (input + size - 1 * sizeof(aes512_t)));
              aes128_t keys[4] = {hasher.key, hasher.key, hasher.key, hasher.key};
              current[0] = aes_encode4(_mm512_loadu_si512(keys), tail[0]);
              current[1] = aes_encode4(_mm512_loadu_si512(keys), tail[1]);
              sum = add_by_64s4(_mm512_loadu_si512(keys), tail[0]);
              sum = shuffle_add4(sum, tail[1]);
              while (size > 128) {
                  tail[0] = _mm512_loadu_si512((aes512_t *) (input + 0 * sizeof(aes512_t)));
                  tail[1] = _mm512_loadu_si512((aes512_t *) (input + 1 * sizeof(aes512_t)));
                  current[0] = aes_encode4(current[0], tail[0]);
                  current[1] = aes_encode4(current[1], tail[1]);
                  sum = shuffle_add4(sum, tail[0]);
                  sum = shuffle_add4(sum, tail[1]);
                  size -= 128;
                  input = ((uint8_t *) input) + 128;
              }
              aes512_t encoded = aes_encode4(current[0], current[1]);
              aes128_t current0 = _mm512_extracti64x2_epi64(encoded, 0);
              aes128_t current1 = _mm512_extracti64x2_epi64(encoded, 1);
              aes128_t current2 = _mm512_extracti64x2_epi64(encoded, 2);
              aes128_t current3 = _mm512_extracti64x2_epi64(encoded, 3);
              aes128_t sum0 = _mm512_extracti64x2_epi64(sum, 0);
              aes128_t sum1 = _mm512_extracti64x2_epi64(sum, 1);
              aes128_t sum2 = _mm512_extracti64x2_epi64(sum, 2);
              aes128_t sum3 = _mm512_extracti64x2_epi64(sum, 3);
              // no vex transition transition, no need to zero uppers
              hasher = hash2(hasher, aes_encode(current0, current1), aes_encode(current2, current3));
              return hash1(hasher, add_by_64s(add_by_64s(sum0, sum1), add_by_64s(sum2, sum3)));
          }
          else {
#endif
              aes256_t tail[2];
              aes256_t current[2];
              aes256_t sum;
              tail[0] =
                      _mm256_lddqu_si256((aes256_t *) (input + size - 2 * sizeof(aes256_t)));
              tail[1] =
                      _mm256_lddqu_si256((aes256_t *) (input + size - 1 * sizeof(aes256_t)));
              current[0] = aes_encode2(_mm256_set_m128i(hasher.key, hasher.key), tail[0]);
              current[1] = aes_encode2(_mm256_set_m128i(hasher.key, hasher.key), tail[1]);
              sum = add_by_64s2(_mm256_set_m128i(hasher.key, hasher.key), tail[0]);
              sum = shuffle_add2(sum, tail[1]);
              while (size > 64) {
                  tail[0] = _mm256_lddqu_si256((aes256_t *) (input + 0 * sizeof(aes256_t)));
                  tail[1] = _mm256_lddqu_si256((aes256_t *) (input + 1 * sizeof(aes256_t)));
                  current[0] = aes_encode2(current[0], tail[0]);
                  current[1] = aes_encode2(current[1], tail[1]);
                  sum = shuffle_add2(sum, tail[0]);
                  sum = shuffle_add2(sum, tail[1]);
                  size -= 64;
                  input = ((uint8_t *) input) + 64;
              }
              aes256_t encoded = aes_encode2(current[0], current[1]);
              aes128_t current0 = _mm256_extractf128_si256(encoded, 0);
              aes128_t current1 = _mm256_extractf128_si256(encoded, 1);
              aes128_t sum0 = _mm256_extractf128_si256(sum, 0);
              aes128_t sum1 = _mm256_extractf128_si256(sum, 1);
              _mm256_zeroupper(); // avoid avx-sse transition penalty
              hasher = hash2(hasher, current0, current1);
              return hash1(hasher, add_by_64s(sum0, sum1));
#ifdef __AVX512DQ__
          }
#endif
#endif
      }
    } else {
      if (size > 16) {
        aes128_t a, b;
#ifdef x86_TARGET
        a = _mm_lddqu_si128((aes128_t *)(input + 0 * sizeof(aes128_t)));
        b = _mm_lddqu_si128((aes128_t *)(input + size - 1 * sizeof(aes128_t)));

#else
        a = (aes128_t)vld1q_u8((uint8_t *)(input + 0 * sizeof(aes128_t)));
        b = (aes128_t)vld1q_u8(
            (uint8_t *)(input + size - 1 * sizeof(aes128_t)));
#endif
        return hash2(hasher, a, b);
      } else {
        uint64_t data[2];
        data[0] = *(uint64_t *)input;
        data[1] = *(uint64_t *)((uint8_t *)input + size - sizeof(uint64_t));
#ifdef x86_TARGET
        aes128_t temp = _mm_set_epi64x(data[1], data[0]);
#else
        aes128_t temp = (aes128_t)vld1q_u64(data);
#endif
        return hash1(hasher, temp);
      }
    }
  }
}

uint64_t finish(ahasher_t hasher) {
    aes128_t combined = aes_decode(hasher.sum, hasher.enc);
    aes128_t result = aes_encode(aes_encode(combined, hasher.key), combined);
#if defined(__amd64__) || defined(_WIN64)
    return _mm_cvtsi128_si64(result);
#elif defined(__i386__) || defined(_WIN32)
    return *(uint64_t*)(&result);
#else
    return vgetq_lane_u64((uint64x2_t)(result), 0);
#endif
}

uint64_t ahash64(const void *buf, size_t size, uint64_t seed) {
    uint64_t keys[4] = {
            0x243f6a8885a308d3ull + seed,
            0x13198a2e03707344ull ^ seed,
            0xa4093822299f31d0ull,
            0x082efa98ec4e6c89ull,
    };
    ahasher_t ahasher = hasher_from_random_state(keys[0], keys[1], keys[2], keys[3]);
    ahasher = hash_write(ahasher, buf, size);
    return finish(ahasher);
}

#else
#endif
