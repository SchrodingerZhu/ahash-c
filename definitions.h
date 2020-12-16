//
// Created by schrodinger on 12/15/20.
//

#ifndef AHASH_DEFINITIONS_H
#define AHASH_DEFINITIONS_H
#include <stdint.h>

#ifndef __has_builtin
#define __has_builtin(x) 0
#endif

#if defined(__clang__) || defined(__GNUC__)
#define FAST_PATH inline __attribute__((always_inline))
#elif defined(_MSC_VER)
#define FAST_PATH inline __forceinline
#else
#define FAST_PATH inline
#endif

#if defined(__amd64__) && defined(__SSSE3__) && defined(__AES__)
#define x86_64_TARGET
#include <immintrin.h>
#include <wmmintrin.h>
typedef __m128i aes128_t;
#elif (defined(__arm64__) || defined(__aarch64__) || defined(_M_ARM)) &&       \
    defined(__ARM_NEON)
#define ARM_TARGET
#if defined(__ARM_NEON) || defined(_MSC_VER)
#include <arm_neon.h>
#endif
/* GCC and LLVM Clang, but not Apple Clang */
#if defined(__GNUC__) && !defined(__apple_build_version__)
#if defined(__ARM_ACLE) || defined(__ARM_FEATURE_CRYPTO)
#include <arm_acle.h>
#endif
#endif
typedef uint8x16_t aes128_t;
#else
#define USE_FALLBACK
#endif

#ifndef USE_FALLBACK

typedef __int128 int128_t;
typedef unsigned __int128 uint128_t;
#define SHUFFLE_MASK                                                           \
  (((uint128_t)(0x020a07000c01030eull) << 64ull) | 0x050f0d0806090b04ull)

static FAST_PATH aes128_t shuffle(aes128_t data) {
#ifdef __SSSE3__
  return _mm_shuffle_epi8(data, (aes128_t)SHUFFLE_MASK);
#elif defined(ARM_TARGET)
  return (aes128_t)vqtbl1q_p8((poly8x16_t)data, (aes128_t)SHUFFLE_MASK);
#elif __has_builtin(__builtin_shuffle)
  typedef uint8_t v16ui __attribute__((vector_size(16)));
  return (aes128_t)__builtin_shuffle((v16ui)data, (v16ui)SHUFFLE_MASK);
#endif
}

static FAST_PATH aes128_t shuffle_add(aes128_t x, aes128_t y) {
#ifdef x86_64_TARGET
  return (aes128_t)_mm_add_epi64(shuffle(x), y);
#elif defined(ARM_TARGET)
  return (aes128_t)vaddq_u64((uint64x2_t)shuffle(x), (uint64x2_t)y);
#elif
  typedef uint64_t v64ui __attribute__((vector_size(16)));
  return (aes128_t)((v64ui)(shuffle(x)) + (v64ui)(y));
#endif
}

static FAST_PATH aes128_t add_shuffle(aes128_t x, aes128_t y) {
#ifdef x86_64_TARGET
  return shuffle((aes128_t)_mm_add_epi64((__m128i)x, (__m128i)y));
#elif defined(ARM_TARGET)
  return shuffle((aes128_t)vaddq_u64((uint64x2_t)(x), (uint64x2_t)y));
#elif
  typedef u_int64_t v64ui __attribute__((vector_size(16)));
  return shuffle((aes128_t)((v64ui)x + (v64ui)y));
#endif
}

static FAST_PATH aes128_t aes_encode(aes128_t x, aes128_t y) {
#ifdef x86_64_TARGET
  return (aes128_t)_mm_aesenc_si128((__m128i)x, (__m128i)y);
#elif defined(ARM_TARGET)
  return (aes128_t)vaesmcq_u8(vaeseq_u8((uint8x16_t)x, (uint8x16_t){})) ^ y;
#endif
}

static FAST_PATH aes128_t aes_decode(aes128_t x, aes128_t y) {
#ifdef x86_64_TARGET
  return (aes128_t)_mm_aesdec_si128((__m128i)x, (__m128i)y);
#elif defined(ARM_TARGET)
  return (aes128_t)vaesimcq_u8(vaesdq_u8((uint8x16_t)x, (uint8x16_t){})) ^ y;
#endif
}
#else
static FAST_PATH uint64_t rotate_left(uint64_t x, uint64_t bit) {
#if __has_builtin(__builtin_rotateleft64)
  // this is bascially a clang builtin
  return __builtin_rotateleft64(x, bit);
#else
  // actually, both arm64 and x86_64 has good codegen
  // with the following on clang and gcc
  return (x >> (64 - bit)) | (x << bit);
#endif
}

static FAST_PATH uint64_t emu_multiply(uint64_t op1, uint64_t op2, uint64_t *hi,
                                       uint64_t *lo) {
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

static FAST_PATH uint64_t folded_multiply(uint64_t s, uint64_t by) {
#if defined(__SIZEOF_INT128__)
  // if int128 is available, then use int128,
  // this should pass for most 64 bit machines
  __int128 result = (__int128)(s) * (__int128)(by);
  return (uint64_t)(result & 0xffffffffffffffff) ^ (uint64_t)(result >> 64);
#elif defined(__clang__)
  // with clang, we can still use TI integers in 32bit mode
  // it has been tested that clang can gen a shorter code here than the next
  // fallback
  typedef unsigned int mul_t __attribute__((mode(TI)));
  mul_t result = (mul_t)(s) * (mul_t)(by);
  return (uint64_t)(result & 0xffffffffffffffff) ^ (uint64_t)(result >> 64);
#else
  // fallback for 32bit machines, this generally do the same thing as clang's
  // TI integers for 32bit
  uint64_t high, low;
  emu_multiply(s, by, &high, &low);
  return high ^ low;
#endif
}
#endif
#endif // AHASH_DEFINITIONS_H
