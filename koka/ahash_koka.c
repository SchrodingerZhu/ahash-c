#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifndef __has_builtin
#  define __has_builtin(x) 0
#endif

#if defined(__clang__) || defined(__GNUC__)
#  define AHASH_FAST_PATH inline __attribute__((always_inline))
#elif defined(_MSC_VER)
#  include <intrin.h>
#  define AHASH_FAST_PATH inline __forceinline
#else
#  define AHASH_FAST_PATH inline
#endif
#if defined(__SSSE3__) && defined(__AES__)
#  define AHASH_x86_TARGET
#  include <immintrin.h>
#  include <wmmintrin.h>
#  ifdef __VAES__
typedef __m256i aes256_t;
#    ifdef __AVX512DQ__
typedef __m512i aes512_t;
#    endif
#  endif
typedef __m128i aes128_t;
#  define AES_OR(a, b) (_mm_or_si128(a, b))
#elif (defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM64)) && \
  defined(__ARM_NEON) && defined(__ARM_FEATURE_CRYPTO)
#  define AHASH_ARM_TARGET
#  ifdef _MSC_VER
#    include <arm64_neon.h>
#  else
#    include <arm_neon.h>
#  endif
typedef uint8x16_t aes128_t;
#  define AES_OR(a, b) (veorq_u8(a, b))
#else
#  define AHASH_USE_FALLBACK
#endif

#ifndef AHASH_USE_FALLBACK
#  if defined(__VAES__) && defined(AHASH_x86_TARGET)
static AHASH_FAST_PATH aes256_t shuffle2(aes256_t data)
{
  const aes256_t mask = _mm256_set_epi64x(
    0x020a07000c01030eull,
    0x050f0d0806090b04ull,
    0x020a07000c01030eull,
    0x050f0d0806090b04ull);
  return _mm256_shuffle_epi8(data, mask);
}
static AHASH_FAST_PATH aes256_t shuffle_add2(aes256_t x, aes256_t y)
{
  return _mm256_add_epi64(shuffle2(x), y);
}
static AHASH_FAST_PATH aes256_t add_by_64s2(aes256_t x, aes256_t y)
{
  return _mm256_add_epi64(x, y);
}
static AHASH_FAST_PATH aes256_t aes_encode2(aes256_t x, aes256_t y)
{
  return _mm256_aesenc_epi128(x, y);
}

#    ifdef __AVX512DQ__
static AHASH_FAST_PATH aes512_t shuffle4(aes512_t data)
{
  const aes512_t mask = _mm512_set_epi64(
    0x020a07000c01030eull,
    0x050f0d0806090b04ull,
    0x020a07000c01030eull,
    0x050f0d0806090b04ull,
    0x020a07000c01030eull,
    0x050f0d0806090b04ull,
    0x020a07000c01030eull,
    0x050f0d0806090b04ull);
  return _mm512_shuffle_epi8(data, mask);
}
static AHASH_FAST_PATH aes512_t shuffle_add4(aes512_t x, aes512_t y)
{
  return _mm512_add_epi64(shuffle4(x), y);
}
static AHASH_FAST_PATH aes512_t add_by_64s4(aes512_t x, aes512_t y)
{
  return _mm512_add_epi64(x, y);
}
static AHASH_FAST_PATH aes512_t aes_encode4(aes512_t x, aes512_t y)
{
  return _mm512_aesenc_epi128(x, y);
}
#    endif
#  endif

static AHASH_FAST_PATH aes128_t shuffle(aes128_t data)
{
#  ifdef AHASH_x86_TARGET
  const aes128_t mask =
    _mm_set_epi64x(0x020a07000c01030eull, 0x050f0d0806090b04ull);
  return _mm_shuffle_epi8(data, mask);
#  elif defined(AHASH_ARM_TARGET) && defined(_MSC_VER)
  static const unsigned long masks[2] = {
    0x020a07000c01030eull, 0x050f0d0806090b04ull};
  return vqtbl1q_p8(data, vld1q_u64(masks));
#  elif defined(AHASH_ARM_TARGET)
  return (aes128_t)vqtbl1q_p8(
    (poly8x16_t)data,
    (aes128_t)(
      ((__int128)(0x020a07000c01030eull) << 64ull) | 0x050f0d0806090b04ull));
#  elif __has_builtin(__builtin_shuffle)
  typedef uint8_t v16ui __attribute__((vector_size(16)));
  return (aes128_t)__builtin_shuffle(
    (v16ui)data,
    (v16ui)(
      ((__int128)(0x020a07000c01030eull) << 64ull) | 0x050f0d0806090b04ull));
#  endif
}

static AHASH_FAST_PATH aes128_t shuffle_add(aes128_t x, aes128_t y)
{
#  ifdef AHASH_x86_TARGET
  return _mm_add_epi64(shuffle(x), y);
#  elif defined(AHASH_ARM_TARGET) && defined(_MSC_VER)
  return vaddq_s64(shuffle(x), y);
#  elif defined(AHASH_ARM_TARGET)
  return (aes128_t)vaddq_s64((int64x2_t)shuffle(x), (int64x2_t)y);
#  elif
  typedef uint64_t v64i __attribute__((vector_size(16)));
  return (aes128_t)((v64i)(shuffle(x)) + (v64i)(y));
#  endif
}

static AHASH_FAST_PATH aes128_t add_by_64s(aes128_t x, aes128_t y)
{
#  ifdef AHASH_x86_TARGET
  return _mm_add_epi64(x, y);
#  elif defined(AHASH_ARM_TARGET) && defined(_MSC_VER)
  return vaddq_s64(x, y);
#  elif defined(AHASH_ARM_TARGET)
  return (aes128_t)vaddq_s64((int64x2_t)x, (int64x2_t)y);
#  elif
  typedef int64_t v64i __attribute__((vector_size(16)));
  return (aes128_t)((v64i)(x) + (v64i)(y));
#  endif
}

// static AHASH_FAST_PATH aes128_t add_shuffle(aes128_t x, aes128_t y)
//{
//#  ifdef AHASH_x86_TARGET
//  return shuffle(_mm_add_epi64(x, y));
//#  elif defined(AHASH_ARM_TARGET) && defined(_MSC_VER)
//  return shuffle(vaddq_s64(x, y));
//#  elif defined(AHASH_ARM_TARGET)
//  return shuffle((aes128_t)vaddq_s64((int64x2_t)(x), (int64x2_t)y));
//#  elif
//  typedef int64_t v64i __attribute__((vector_size(16)));
//  return shuffle((aes128_t)((v64i)x + (v64i)y));
//#  endif
//}

static AHASH_FAST_PATH aes128_t aes_encode(aes128_t x, aes128_t y)
{
#  ifdef AHASH_x86_TARGET
  return _mm_aesenc_si128(x, y);
#  elif defined(AHASH_ARM_TARGET) && defined(_MSC_VER)
  static const unsigned long zero[2] = {0, 0};
  return veorq_u8(vaesmcq_u8(vaeseq_u8(x, vld1q_u64(zero))), y);
#  elif defined(AHASH_ARM_TARGET)
  return (aes128_t)vaesmcq_u8(vaeseq_u8((uint8x16_t)x, (uint8x16_t){})) ^ y;
#  endif
}

static AHASH_FAST_PATH aes128_t aes_decode(aes128_t x, aes128_t y)
{
#  ifdef AHASH_x86_TARGET
  return _mm_aesdec_si128(x, y);
#  elif defined(AHASH_ARM_TARGET) && defined(_MSC_VER)
  static const unsigned long zero[2] = {0, 0};
  return veorq_u8(vaesimcq_u8(vaesdq_u8(x, vld1q_u64(zero))), y);
#  elif defined(AHASH_ARM_TARGET)
  return (aes128_t)vaesimcq_u8(vaesdq_u8((uint8x16_t)x, (uint8x16_t){})) ^ y;
#  endif
}
#else
static AHASH_FAST_PATH uint64_t rotate_left(uint64_t x, uint64_t bit)
{
#  if __has_builtin(__builtin_AHASH_ROTateleft64)
  // this is bascially a clang builtin
  return __builtin_AHASH_ROTateleft64(x, bit);
#  elif defined(_MSC_VER)
  return _AHASH_ROTl64(x, bit);
#  else
  // actually, both arm64 and x86_64 has good codegen
  // with the following on clang and gcc
  return (x >> (64 - bit)) | (x << bit);
#  endif
}

static AHASH_FAST_PATH void
emu_multiply(uint64_t op1, uint64_t op2, uint64_t* hi, uint64_t* lo)
{
  uint64_t u1 = (op1 & 0xffffffff);
  uint64_t v1 = (op2 & 0xffffffff);
  uint64_t t = (u1 * v1);
  uint64_t w3 = (t & 0xffffffff);
  uint64_t k = (t >> 32);

  op1 >>= 32;
  t = (op1 * v1) + k;
  k = (t & 0xffffffff);
  uint64_t w1 = (t >> 32);

  op2 >>= 32;
  t = (u1 * op2) + k;
  k = (t >> 32);

  *hi = (op1 * op2) + w1 + k;
  *lo = (t << 32) + w3;
}

static AHASH_FAST_PATH uint64_t folded_multiply(uint64_t s, uint64_t by)
{
#  if defined(__SIZEOF_INT128__)
  // if int128 is available, then use int128,
  // this should pass for most 64 bit machines
  __int128 result = (__int128)(s) * (__int128)(by);
  return (uint64_t)(result & 0xffffffffffffffff) ^ (uint64_t)(result >> 64);
#  elif defined(_MSC_VER) && !defined(_M_ARM) && !defined(_M_ARM64)
  uint64_t high, low;
  low = _umul128(s, by, &high);
  return high ^ low;
#  else
  // fallback for 32bit machines, this generally do the same thing as clang's
  // TI integers for 32bit
  uint64_t high, low;
  emu_multiply(s, by, &high, &low);
  return high ^ low;
#  endif
}
#endif

#ifndef AHASH_USE_FALLBACK
typedef struct ahasher_s
{
  aes128_t enc;
  aes128_t sum;
  aes128_t key;
} ahasher_t;
#else
#  include <string.h>
#  define AHASH_MULTIPLIER 6364136223846793005ull
#  define AHASH_ROT 23
typedef struct ahasher_s
{
  uint64_t buffer;
  uint64_t pad;
  uint64_t extra_keys[2];
} ahasher_t;
#endif

ahasher_t
hasher_from_random_state(uint64_t k0, uint64_t k1, uint64_t k2, uint64_t k3);

#define WRITE_API(TYPE) ahasher_t write_##TYPE(ahasher_t hasher, TYPE value);

WRITE_API(uint64_t);
WRITE_API(int64_t);
WRITE_API(uint32_t);
WRITE_API(int32_t);
WRITE_API(uint16_t);
WRITE_API(int16_t);
WRITE_API(uint8_t);
WRITE_API(int8_t);

ahasher_t add_length(ahasher_t hasher, size_t length);
ahasher_t
hash_write(ahasher_t hasher, const void* __restrict__ input, size_t size);
uint64_t finish(ahasher_t hasher);

typedef struct random_state_s
{
  uint64_t keys[4];
} random_state_t;

#define CREATE_HASHER(state) \
  hasher_from_random_state( \
    state.keys[0], state.keys[1], state.keys[2], state.keys[3])

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
  counter += stack_position;
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

random_state_t new_state_from_seed(int32_t y)
// FIXME: current koka only has good int32 support
{
  uint64_t x = y;
  uint64_t seed = x * x + (~x << 32u);
  random_state_t res;
  res.keys[0] = PI[0] ^ seed, res.keys[1] = PI[1] + seed;
  res.keys[2] = PI[2];
  res.keys[3] = PI[3];
  return res;
}

#ifndef AHASH_USE_FALLBACK

ahasher_t new_with_key(aes128_t key1, aes128_t key2)
{
  ahasher_t result;
  result.enc = key1;
  result.sum = key2;
  result.key = AES_OR(key1, key2);
  return result;
}

ahasher_t
hasher_from_random_state(uint64_t k0, uint64_t k1, uint64_t k2, uint64_t k3)
{
  aes128_t key1, key2;
#  ifdef AHASH_x86_TARGET
  key1 = _mm_set_epi64x(k1, k0);
  key2 = _mm_set_epi64x(k3, k2);
#  else
  uint64_t keys[4] = {k0, k1, k2, k3};
  key1 = (aes128_t)vld1q_u64(keys);
  key2 = (aes128_t)vld1q_u64(keys + 2);
#  endif
  return new_with_key(key1, key2);
}

static AHASH_FAST_PATH aes128_t add_low(aes128_t a, uint64_t b)
{
#  ifdef AHASH_x86_TARGET
  aes128_t temp = _mm_set_epi64x(0, b);
  return _mm_add_epi64(a, temp);
#  else
  uint64_t temp[2] = {b, 0};
  uint64x2_t operand = vld1q_u64(temp);
  return (aes128_t)vaddq_u64((uint64x2_t)a, operand);
#  endif
}

// static AHASH_FAST_PATH aes128_t add_high(aes128_t a, uint64_t b)
//{
//#  ifdef AHASH_x86_TARGET
//  aes128_t temp = _mm_set_epi64x(b, 0);
//  return _mm_add_epi64(a, temp);
//#  else
//  uint64_t temp[2] = {0, b};
//  uint64x2_t operand = vld1q_u64(temp);
//  return (aes128_t)vaddq_u64((uint64x2_t)a, operand);
//#  endif
//}

ahasher_t add_length(ahasher_t hasher, size_t length)
{
  hasher.enc = add_low(hasher.enc, length);
  return hasher;
}

ahasher_t hash1(ahasher_t hasher, aes128_t v1)
{
  hasher.enc = aes_encode(hasher.enc, v1);
  hasher.sum = shuffle_add(hasher.sum, v1);
  return hasher;
}

ahasher_t hash2(ahasher_t hasher, aes128_t v1, aes128_t v2)
{
  hasher.enc = aes_encode(hasher.enc, v1);
  hasher.sum = shuffle_add(hasher.sum, v1);
  hasher.enc = aes_encode(hasher.enc, v2);
  hasher.sum = shuffle_add(hasher.sum, v2);
  return hasher;
}

ahasher_t write_uint64_t(ahasher_t hasher, uint64_t value)
{
#  ifdef AHASH_x86_TARGET
  aes128_t temp = _mm_set_epi64x(value, 0);
  return hash1(hasher, temp);
#  else
  uint64_t temp[2] = {0, value};
  aes128_t key = (aes128_t)vld1q_u64(temp);
  return hash1(hasher, key);
#  endif
}

#  define WRITABLE(TYPE) \
    ahasher_t write_##TYPE(ahasher_t hasher, TYPE value) \
    { \
      return write_uint64_t(hasher, (uint64_t)value); \
    }

WRITABLE(uint8_t)
WRITABLE(int8_t)
WRITABLE(uint16_t)
WRITABLE(int16_t)
WRITABLE(uint32_t)
WRITABLE(int32_t)
WRITABLE(int64_t)

ahasher_t
hash_write(ahasher_t hasher, const void* __restrict__ input, size_t size)
{
  hasher = add_length(hasher, size);
  if (size < 8)
  {
    uint64_t data[2];
    if (size >= 2)
    {
      if (size >= 4)
      {
        data[0] = *(uint32_t*)input;
        data[1] = *(uint32_t*)((uint8_t*)input + size - sizeof(uint32_t));
      }
      else
      {
        data[0] =
          *(uint16_t*)
            input; /// TODO: aarch64 should be good with unaligned access
        data[1] = *((uint8_t*)input + size - 1);
      }
    }
    else
    {
      if (size > 0)
      {
        data[0] = *((uint8_t*)input);
        data[1] = 0;
      }
      else
      {
        data[1] = data[0] = 0;
      }
    }
#  ifdef AHASH_x86_TARGET
    aes128_t temp = _mm_set_epi64x(data[1], data[0]);
#  else
    aes128_t temp = (aes128_t)vld1q_u64(data);
#  endif
    return hash1(hasher, temp);
  }
  else
  {
    if (size > 32)
    {
      if (size > 64)
      {
#  if !(defined(__VAES__) && defined(AHASH_x86_TARGET))
        aes128_t tail[4];
        aes128_t current[4];
        aes128_t sum[2];
#    if defined(AHASH_x86_TARGET)
        tail[0] = /// TODO: whether _mm_lddqu_si128 is good enough here for
                  /// unaligned access
          _mm_lddqu_si128(
            (aes128_t*)((uint8_t*)input + size - 4 * sizeof(aes128_t)));
        tail[1] = _mm_lddqu_si128(
          (aes128_t*)((uint8_t*)input + size - 3 * sizeof(aes128_t)));
        tail[2] = _mm_lddqu_si128(
          (aes128_t*)((uint8_t*)input + size - 2 * sizeof(aes128_t)));
        tail[3] = _mm_lddqu_si128(
          (aes128_t*)((uint8_t*)input + size - 1 * sizeof(aes128_t)));
#    else
        tail[0] = (aes128_t)vld1q_u8(
          (uint8_t*)((uint8_t*)input + size - 4 * sizeof(aes128_t)));
        tail[1] = (aes128_t)vld1q_u8(
          (uint8_t*)((uint8_t*)input + size - 3 * sizeof(aes128_t)));
        tail[2] = (aes128_t)vld1q_u8(
          (uint8_t*)((uint8_t*)input + size - 2 * sizeof(aes128_t)));
        tail[3] = (aes128_t)vld1q_u8(
          (uint8_t*)((uint8_t*)input + size - 1 * sizeof(aes128_t)));
#    endif
        current[0] = aes_encode(hasher.key, tail[0]);
        current[1] = aes_encode(hasher.key, tail[1]);
        current[2] = aes_encode(hasher.key, tail[2]);
        current[3] = aes_encode(hasher.key, tail[3]);
        sum[0] = add_by_64s(hasher.key, tail[0]);
        sum[1] = add_by_64s(hasher.key, tail[1]);
        sum[0] = shuffle_add(sum[0], tail[2]);
        sum[1] = shuffle_add(sum[1], tail[3]);
        while (size > 64)
        {
#    ifdef AHASH_x86_TARGET
          tail[0] = _mm_lddqu_si128(
            (aes128_t*)((uint8_t*)input + 0 * sizeof(aes128_t)));
          tail[1] = _mm_lddqu_si128(
            (aes128_t*)((uint8_t*)input + 1 * sizeof(aes128_t)));
          tail[2] = _mm_lddqu_si128(
            (aes128_t*)((uint8_t*)input + 2 * sizeof(aes128_t)));
          tail[3] = _mm_lddqu_si128(
            (aes128_t*)((uint8_t*)input + 3 * sizeof(aes128_t)));
#    else
          tail[0] = (aes128_t)vld1q_u8(
            (uint8_t*)((uint8_t*)input + 0 * sizeof(aes128_t)));
          tail[1] = (aes128_t)vld1q_u8(
            (uint8_t*)((uint8_t*)input + 1 * sizeof(aes128_t)));
          tail[2] = (aes128_t)vld1q_u8(
            (uint8_t*)((uint8_t*)input + 2 * sizeof(aes128_t)));
          tail[3] = (aes128_t)vld1q_u8(
            (uint8_t*)((uint8_t*)input + 3 * sizeof(aes128_t)));
#    endif
          current[0] = aes_encode(current[0], tail[0]);
          current[1] = aes_encode(current[1], tail[1]);
          current[2] = aes_encode(current[2], tail[2]);
          current[3] = aes_encode(current[3], tail[3]);
          sum[0] = shuffle_add(sum[0], tail[0]);
          sum[1] = shuffle_add(sum[1], tail[1]);
          sum[0] = shuffle_add(sum[0], tail[2]);
          sum[1] = shuffle_add(sum[1], tail[3]);
          size -= 64;
          input = ((uint8_t*)input) + 64;
        }
        hasher = hash2(
          hasher,
          aes_encode(current[0], current[1]),
          aes_encode(current[2], current[3]));
        return hash1(hasher, add_by_64s(sum[0], sum[1]));
      }
      else
      {
        aes128_t head[2], tail[2];
#    ifdef AHASH_x86_TARGET
        head[0] =
          _mm_lddqu_si128((aes128_t*)((uint8_t*)input + 0 * sizeof(aes128_t)));
        head[1] =
          _mm_lddqu_si128((aes128_t*)((uint8_t*)input + 1 * sizeof(aes128_t)));
        tail[0] = _mm_lddqu_si128(
          (aes128_t*)((uint8_t*)input + size - 2 * sizeof(aes128_t)));
        tail[1] = _mm_lddqu_si128(
          (aes128_t*)((uint8_t*)input + size - 1 * sizeof(aes128_t)));
#    else
        head[0] = (aes128_t)vld1q_u8(
          (uint8_t*)((uint8_t*)input + 0 * sizeof(aes128_t)));
        head[1] = (aes128_t)vld1q_u8(
          (uint8_t*)((uint8_t*)input + 1 * sizeof(aes128_t)));
        tail[0] = (aes128_t)vld1q_u8(
          (uint8_t*)((uint8_t*)input + size - 2 * sizeof(aes128_t)));
        tail[1] = (aes128_t)vld1q_u8(
          (uint8_t*)((uint8_t*)input + size - 1 * sizeof(aes128_t)));
#    endif
        hasher = hash2(hasher, head[0], head[1]);
        return hash2(hasher, tail[0], tail[1]);
#  else // x86_64 VAES intruction set
#    ifdef __AVX512DQ__
        if (size > 128)
        {
          aes512_t tail[2];
          aes512_t current[2];
          aes512_t sum;
          tail[0] = _mm512_loadu_si512(
            (aes512_t*)((uint8_t*)input + size - 2 * sizeof(aes512_t)));
          tail[1] = _mm512_loadu_si512(
            (aes512_t*)((uint8_t*)input + size - 1 * sizeof(aes512_t)));
          aes128_t keys[4] = {hasher.key, hasher.key, hasher.key, hasher.key};
          current[0] = aes_encode4(_mm512_loadu_si512(keys), tail[0]);
          current[1] = aes_encode4(_mm512_loadu_si512(keys), tail[1]);
          sum = add_by_64s4(_mm512_loadu_si512(keys), tail[0]);
          sum = shuffle_add4(sum, tail[1]);
          while (size > 128)
          {
            tail[0] = _mm512_loadu_si512(
              (aes512_t*)((uint8_t*)input + 0 * sizeof(aes512_t)));
            tail[1] = _mm512_loadu_si512(
              (aes512_t*)((uint8_t*)input + 1 * sizeof(aes512_t)));
            current[0] = aes_encode4(current[0], tail[0]);
            current[1] = aes_encode4(current[1], tail[1]);
            sum = shuffle_add4(sum, tail[0]);
            sum = shuffle_add4(sum, tail[1]);
            size -= 128;
            input = ((uint8_t*)input) + 128;
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
          hasher = hash2(
            hasher,
            aes_encode(current0, current1),
            aes_encode(current2, current3));
          return hash1(
            hasher, add_by_64s(add_by_64s(sum0, sum1), add_by_64s(sum2, sum3)));
        }
        else
        {
#    endif
          aes256_t tail[2];
          aes256_t current[2];
          aes256_t sum;
          tail[0] = _mm256_lddqu_si256(
            (aes256_t*)(input + size - 2 * sizeof(aes256_t)));
          tail[1] = _mm256_lddqu_si256(
            (aes256_t*)(input + size - 1 * sizeof(aes256_t)));
          current[0] =
            aes_encode2(_mm256_set_m128i(hasher.key, hasher.key), tail[0]);
          current[1] =
            aes_encode2(_mm256_set_m128i(hasher.key, hasher.key), tail[1]);
          sum = add_by_64s2(_mm256_set_m128i(hasher.key, hasher.key), tail[0]);
          sum = shuffle_add2(sum, tail[1]);
          while (size > 64)
          {
            tail[0] = _mm256_lddqu_si256(
              (aes256_t*)((uint8_t*)input + 0 * sizeof(aes256_t)));
            tail[1] = _mm256_lddqu_si256(
              (aes256_t*)((uint8_t*)input + 1 * sizeof(aes256_t)));
            current[0] = aes_encode2(current[0], tail[0]);
            current[1] = aes_encode2(current[1], tail[1]);
            sum = shuffle_add2(sum, tail[0]);
            sum = shuffle_add2(sum, tail[1]);
            size -= 64;
            input = ((uint8_t*)input) + 64;
          }
          aes256_t encoded = aes_encode2(current[0], current[1]);
          aes128_t current0 = _mm256_extractf128_si256(encoded, 0);
          aes128_t current1 = _mm256_extractf128_si256(encoded, 1);
          aes128_t sum0 = _mm256_extractf128_si256(sum, 0);
          aes128_t sum1 = _mm256_extractf128_si256(sum, 1);
          _mm256_zeroupper(); // avoid avx-sse transition penalty
          hasher = hash2(hasher, current0, current1);
          return hash1(hasher, add_by_64s(sum0, sum1));
#    ifdef __AVX512DQ__
        }
#    endif
#  endif
      }
    }
    else
    {
      if (size > 16)
      {
        aes128_t a, b;
#  ifdef AHASH_x86_TARGET
        a =
          _mm_lddqu_si128((aes128_t*)((uint8_t*)input + 0 * sizeof(aes128_t)));
        b = _mm_lddqu_si128(
          (aes128_t*)((uint8_t*)input + size - 1 * sizeof(aes128_t)));

#  else
        a = (aes128_t)vld1q_u8(
          (uint8_t*)((uint8_t*)input + 0 * sizeof(aes128_t)));
        b = (aes128_t)vld1q_u8(
          (uint8_t*)((uint8_t*)input + size - 1 * sizeof(aes128_t)));
#  endif
        return hash2(hasher, a, b);
      }
      else
      {
        uint64_t data[2];
        data[0] = *(uint64_t*)input;
        data[1] = *(uint64_t*)((uint8_t*)input + size - sizeof(uint64_t));
#  ifdef AHASH_x86_TARGET
        aes128_t temp = _mm_set_epi64x(data[1], data[0]);
#  else
        aes128_t temp = (aes128_t)vld1q_u64(data);
#  endif
        return hash1(hasher, temp);
      }
    }
  }
}

uint64_t finish(ahasher_t hasher)
{
  aes128_t combined = aes_decode(hasher.sum, hasher.enc);
  aes128_t result = aes_encode(aes_encode(combined, hasher.key), combined);
#  if defined(__amd64__) || defined(_WIN64)
  return _mm_cvtsi128_si64(result);
#  elif defined(__i386__) || defined(_WIN32)
  return *(uint64_t*)(&result);
#  else
  return vgetq_lane_u64((uint64x2_t)(result), 0);
#  endif
}
#else

ahasher_t
hasher_from_random_state(uint64_t k0, uint64_t k1, uint64_t k2, uint64_t k3)
{
  ahasher_t result;
  result.buffer = k0;
  result.pad = k1;
  result.extra_keys[0] = k2;
  result.extra_keys[1] = k3;
  return result;
}

static AHASH_FAST_PATH ahasher_t update(ahasher_t hasher, int64_t data)
{
  hasher.buffer = folded_multiply(data ^ hasher.buffer, AHASH_MULTIPLIER);
  return hasher;
}

static AHASH_FAST_PATH ahasher_t
update2(ahasher_t hasher, uint64_t data1, uint64_t data2)
{
  uint64_t combined =
    folded_multiply(data1 ^ hasher.extra_keys[0], data2 ^ hasher.extra_keys[1]);
  hasher.buffer =
    rotate_left((combined + hasher.buffer) ^ hasher.pad, AHASH_ROT);
  return hasher;
}

#  define WRITABLE(TYPE) \
    ahasher_t write_##TYPE(ahasher_t hasher, TYPE value) \
    { \
      return update(hasher, (uint64_t)value); \
    }

WRITABLE(uint8_t)
WRITABLE(int8_t)
WRITABLE(uint16_t)
WRITABLE(int16_t)
WRITABLE(uint32_t)
WRITABLE(int32_t)
WRITABLE(int64_t)
WRITABLE(uint64_t)

ahasher_t
hash_write(ahasher_t hasher, const void* __restrict__ input, size_t size)
{
  hasher.buffer = (hasher.buffer + size) * AHASH_MULTIPLIER;
  if (size > 8)
  {
    if (size > 16)
    {
      uint64_t temp[2];
      memcpy(temp, ((uint8_t*)input + size - 16), 16);
      hasher = update2(hasher, temp[0], temp[1]);
      while (size > 16)
      {
        memcpy(temp, input, 16);
        hasher = update2(hasher, temp[0], temp[1]);
        size -= 16;
        input = (uint8_t*)input + 16;
      }
      return hasher;
    }
    else
    {
      uint64_t temp[2] = {0, 0};
      memcpy(temp, input, 8);
      memcpy(temp + 1, (uint8_t*)input + size - 8, 8);
      return update2(hasher, temp[0], temp[1]);
    }
  }
  else
  {
    if (size >= 2)
    {
      if (size >= 4)
      {
        uint64_t temp[2] = {0, 0};
        memcpy(temp, input, 4);
        memcpy(temp + 1, (uint8_t*)input + size - 4, 4);
        return update2(hasher, temp[0], temp[1]);
      }
      else
      {
        uint64_t temp[2] = {0, 0};
        memcpy(temp, input, 2);
        memcpy(temp + 1, (uint8_t*)input + size - 1, 1);
        return update2(hasher, temp[0], temp[1]);
      }
    }
    else
    {
      if (size > 0)
      {
        return update(hasher, *(uint8_t*)(input));
      }
    }
  }
  return hasher;
}

uint64_t finish(ahasher_t hasher)
{
  size_t rot = hasher.buffer & 63;
  return rotate_left(folded_multiply(hasher.buffer, hasher.pad), rot);
}
#endif

#if defined(__x86_64__) || defined(_WIN64)
#  define ARCH "x86_64"
#elif defined(__i386__) || defined(_WIN32)
#  define ARCH "x86"
#elif defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM64)
#  define ARCH "arm64"
#elif defined(__arm__) || defined(_M_ARM)
#  define ARCH "arm"
#else
#  define ARCH "generic"
#endif

#if defined(__SSSE3__) && defined(__AES__)
#  define AES_EXTENSION "+ssse3+aes"
#elif defined(__ARM_FEATURE_CRYPTO)
#  define AES_EXTENSION "+crypto"
#else
#  define AES_EXTENSION ""
#endif

#if defined(__ARM_NEON)
#  define NEON_EXTENSION "+neon"
#else
#  define NEON_EXTENSION ""
#endif

#if defined(__VAES__)
#  define VAES_EXTENSION "+vaes"
#else
#  define VAES_EXTENSION ""
#endif

#if defined(__AVX512DQ__) && defined(__VAES__)
#  define AVX512_EXTENSION "+avx512"
#else
#  define AVX512_EXTENSION ""
#endif

#if defined(__AVX2__) && defined(__VAES__)
#  define AVX2_EXTENSION "+avx2"
#else
#  define AVX2_EXTENSION ""
#endif

kk_define_string_literal(
  static,
  AHASH_VERSION,
  32,
  ARCH AES_EXTENSION NEON_EXTENSION VAES_EXTENSION AVX2_EXTENSION
    AVX512_EXTENSION);

typedef struct ahasher_wrapper
{
  struct kk_ahash__hasher_s _base;
  ahasher_t _inner;
} ahasher_wrapper_t;

typedef struct random_state_wrapper
{
  struct kk_ahash__random_state_s _base;
  random_state_t _inner;
} random_state_wrapper_t;

static kk_string_t kk_ahash_version(void)
{
  return AHASH_VERSION;
}

static kk_unit_t reinitialize_global_seed(kk_context_t* _ctx)
{
  PI2[0] = kk_srandom_uint64(_ctx);
  PI2[1] = kk_srandom_uint64(_ctx);
  PI2[2] = kk_srandom_uint64(_ctx);
  PI2[3] = kk_srandom_uint64(_ctx);
  return kk_Unit;
}

static kk_ahash__random_state next_random_state(kk_context_t* _ctx)
{
  random_state_wrapper_t* state =
    kk_block_alloc_as(random_state_wrapper_t, 0, 0, _ctx);
  state->_inner = new_state();
  return kk_datatype_from_ptr(&state->_base._block);
}

static kk_ahash__random_state seed_state(int32_t seed, kk_context_t* _ctx)
{
  random_state_wrapper_t* state =
    kk_block_alloc_as(random_state_wrapper_t, 0, 0, _ctx);
  state->_inner = new_state_from_seed(seed);
  return kk_datatype_from_ptr(&state->_base._block);
}

static kk_ahash__hasher
create_hasher(kk_ahash__random_state state, kk_context_t* _ctx)
{
  random_state_wrapper_t* s = (random_state_wrapper_t*)(state.ptr);
  ahasher_wrapper_t* hasher = kk_block_alloc_as(ahasher_wrapper_t, 0, 0, _ctx);
  hasher->_inner = CREATE_HASHER(s->_inner);
  if (kk_ahash__random_state_is_unique(state))
  {
    kk_ahash__random_state_free(state);
  }
  else
  {
    kk_ahash__random_state_decref(state, _ctx);
  }
  return kk_datatype_from_ptr(&hasher->_base._block);
}

static kk_integer_t
kk_hasher_finish(kk_ahash__hasher hasher, kk_context_t* _ctx)
{
  /// TODO: it is better to return uint64, but Koka current do no have this type
  ahasher_wrapper_t* h = (ahasher_wrapper_t*)(hasher.ptr);
  uint64_t res = finish(h->_inner);
  if (kk_ahash__hasher_is_unique(hasher))
  {
    kk_ahash__hasher_free(hasher);
  }
  else
  {
    kk_ahash__hasher_decref(hasher, _ctx);
  }
  return kk_integer_from_uint64(res, _ctx);
}

/// FIXME: this is a dirty hack
typedef struct kk_bigint_s
{
  kk_block_t _block;
#if KK_INTPTR_SIZE >= 8
  uint8_t is_neg : 1; // negative
  uint16_t extra : 15; // extra digits available: `sizeof(digits) ==
                       // (count+extra)*sizeof(kk_digit_t)`
  uint64_t count : 48; // count of digits in the number
#else
  uint8_t is_neg;
  uint16_t extra;
  uint32_t count;
#endif
  uint64_t digits[1]; // digits from least-significant to most significant.
} kk_bigint_t;

static kk_ahash__hasher kk_hasher_write_int(
  kk_ahash__hasher hasher, kk_integer_t data, kk_context_t* _ctx)
{
  /// TODO: Do we need type masks
  ahasher_t h = ((ahasher_wrapper_t*)(hasher.ptr))->_inner;
  if (kk_is_smallint(data))
  {
    h = write_uint64_t(h, data.value);
  }
  else
  {
    kk_bigint_t* value = (kk_bigint_t*)(data.value);
    h = write_uint64_t(h, ((uint64_t)value->is_neg << 17) + value->extra);
    h = hash_write(h, value->digits, sizeof(uint64_t) * value->count);
  }
  if (kk_ahash__hasher_is_unique(hasher))
  {
    ((ahasher_wrapper_t*)(hasher.ptr))->_inner = h; // reuse
    return hasher;
  }
  else
  {
    kk_ahash__hasher_decref(hasher, _ctx);
    ahasher_wrapper_t* new_hasher =
      kk_block_alloc_as(ahasher_wrapper_t, 0, 0, _ctx);
    new_hasher->_inner = h;
    return kk_datatype_from_ptr(&new_hasher->_base._block);
  }
}

static kk_ahash__hasher
kk_hasher_write_str(kk_ahash__hasher hasher, kk_string_t x, kk_context_t* _ctx)
{
  /// TODO: Do we need type masks
  ahasher_t h = ((ahasher_wrapper_t*)(hasher.ptr))->_inner;
  struct kk_string_s* data = (struct kk_string_s*)(x.ptr);
  if (kk_datatype_is_singleton(x))
  {
    h = write_uint64_t(h, 0);
  }
  else if (kk_basetype_has_tag(data, KK_TAG_STRING_SMALL))
  {
    kk_string_small_t str =
      kk_basetype_as_assert(kk_string_small_t, data, KK_TAG_STRING_SMALL);
    h = hash_write(h, str->u.str, strlen((const char*)str->u.str));
  }
  else if (kk_basetype_has_tag(data, KK_TAG_STRING))
  {
    kk_string_normal_t str =
      kk_basetype_as_assert(kk_string_normal_t, data, KK_TAG_STRING);
    h = hash_write(h, str->str, str->length);
  }
  else if (kk_basetype_has_tag(data, KK_TAG_STRING_RAW))
  {
    kk_string_raw_t str =
      kk_basetype_as_assert(kk_string_raw_t, data, KK_TAG_STRING_RAW);
    h = hash_write(h, str->cstr, str->length);
  }
  // clean up string
  if (!kk_datatype_is_singleton(x))
  {
    if (kk_datatype_is_unique(x))
    {
      kk_string_drop(x, _ctx);
    }
    else
    {
      kk_datatype_decref(x, _ctx);
    }
  }
  // clean up hasher
  if (kk_ahash__hasher_is_unique(hasher))
  {
    ((ahasher_wrapper_t*)(hasher.ptr))->_inner = h; // reuse
    return hasher;
  }
  else
  {
    kk_ahash__hasher_decref(hasher, _ctx);
    ahasher_wrapper_t* new_hasher =
      kk_block_alloc_as(ahasher_wrapper_t, 0, 0, _ctx);
    new_hasher->_inner = h;
    return kk_datatype_from_ptr(&new_hasher->_base._block);
  }
}

#define TRIVIAL_TYPE_WRITE(TYPE) \
  static kk_ahash__hasher kk_hasher_write_##TYPE( \
    kk_ahash__hasher hasher, TYPE data, kk_context_t* _ctx) \
  { \
    ahasher_t h = ((ahasher_wrapper_t*)(hasher.ptr))->_inner; \
    h = write_uint64_t(h, (uint64_t)(data)); \
    if (kk_ahash__hasher_is_unique(hasher)) \
    { \
      ((ahasher_wrapper_t*)(hasher.ptr))->_inner = h; \
      return hasher; \
    } \
    else \
    { \
      kk_ahash__hasher_decref(hasher, _ctx); \
      ahasher_wrapper_t* new_hasher = \
        kk_block_alloc_as(ahasher_wrapper_t, 0, 0, _ctx); \
      new_hasher->_inner = h; \
      return kk_datatype_from_ptr(&new_hasher->_base._block); \
    } \
  }

TRIVIAL_TYPE_WRITE(int32_t);
TRIVIAL_TYPE_WRITE(int16_t);
TRIVIAL_TYPE_WRITE(int8_t);
TRIVIAL_TYPE_WRITE(uint8_t);
TRIVIAL_TYPE_WRITE(size_t);
TRIVIAL_TYPE_WRITE(kk_char_t);