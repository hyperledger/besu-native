/*
 * Copyright 2012, Samuel Neves <sneves@dei.uc.pt>.
 * Copyright Hyperledger Besu Contributors.
 *
 * Copied and adapted from BLAKE2 reference source code (https://github.com/BLAKE2/BLAKE2)
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#ifdef __APPLE__
#include <machine/endian.h>
#include <libkern/OSByteOrder.h>
#define be32toh(x) OSSwapBigToHostInt32(x)
#else
#include <endian.h>
#endif

#include "blake2.h"
#include "blake2-impl.h"

#include "blake2-config.h"

#ifdef _MSC_VER
#include <intrin.h> /* for _mm_set_epi64x */
#endif
#include <emmintrin.h>
#if defined(HAVE_SSSE3)
#include <tmmintrin.h>
#endif
#if defined(HAVE_SSE41)
#include <smmintrin.h>
#endif
#if defined(HAVE_AVX)
#include <immintrin.h>
#endif
#if defined(HAVE_XOP)
#include <x86intrin.h>
#endif

#include "blake2b-round.h"

static const uint64_t blake2b_IV[8] =
{
  0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL,
  0x3c6ef372fe94f82bULL, 0xa54ff53a5f1d36f1ULL,
  0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
  0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL
};

static void blake2b_compress(uint8_t out[BLAKE2B_OUTBYTES], const uint32_t rounds, const uint64_t h[8], const uint8_t block[128], const uint64_t t[2], const uint64_t f[2])
{
  __m128i row1l, row1h;
  __m128i row2l, row2h;
  __m128i row3l, row3h;
  __m128i row4l, row4h;
  __m128i b0, b1;
  __m128i t0, t1;
  size_t i, round;
#if defined(HAVE_SSSE3) && !defined(HAVE_XOP)
  const __m128i r16 = _mm_setr_epi8( 2, 3, 4, 5, 6, 7, 0, 1, 10, 11, 12, 13, 14, 15, 8, 9 );
  const __m128i r24 = _mm_setr_epi8( 3, 4, 5, 6, 7, 0, 1, 2, 11, 12, 13, 14, 15, 8, 9, 10 );
#endif
#if defined(HAVE_SSE41)
  const __m128i m0 = LOADU( block + 00 );
  const __m128i m1 = LOADU( block + 16 );
  const __m128i m2 = LOADU( block + 32 );
  const __m128i m3 = LOADU( block + 48 );
  const __m128i m4 = LOADU( block + 64 );
  const __m128i m5 = LOADU( block + 80 );
  const __m128i m6 = LOADU( block + 96 );
  const __m128i m7 = LOADU( block + 112 );
#else
  const uint64_t  m0 = load64(block +  0 * sizeof(uint64_t));
  const uint64_t  m1 = load64(block +  1 * sizeof(uint64_t));
  const uint64_t  m2 = load64(block +  2 * sizeof(uint64_t));
  const uint64_t  m3 = load64(block +  3 * sizeof(uint64_t));
  const uint64_t  m4 = load64(block +  4 * sizeof(uint64_t));
  const uint64_t  m5 = load64(block +  5 * sizeof(uint64_t));
  const uint64_t  m6 = load64(block +  6 * sizeof(uint64_t));
  const uint64_t  m7 = load64(block +  7 * sizeof(uint64_t));
  const uint64_t  m8 = load64(block +  8 * sizeof(uint64_t));
  const uint64_t  m9 = load64(block +  9 * sizeof(uint64_t));
  const uint64_t m10 = load64(block + 10 * sizeof(uint64_t));
  const uint64_t m11 = load64(block + 11 * sizeof(uint64_t));
  const uint64_t m12 = load64(block + 12 * sizeof(uint64_t));
  const uint64_t m13 = load64(block + 13 * sizeof(uint64_t));
  const uint64_t m14 = load64(block + 14 * sizeof(uint64_t));
  const uint64_t m15 = load64(block + 15 * sizeof(uint64_t));
#endif
  row1l = LOADU( &h[0] );
  row1h = LOADU( &h[2] );
  row2l = LOADU( &h[4] );
  row2h = LOADU( &h[6] );
  row3l = LOADU( &blake2b_IV[0] );
  row3h = LOADU( &blake2b_IV[2] );
  row4l = _mm_xor_si128( LOADU( &blake2b_IV[4] ), LOADU( &t[0] ) );
  row4h = _mm_xor_si128( LOADU( &blake2b_IV[6] ), LOADU( &f[0] ) );
  for( i = 0; i < rounds; i++) {
    round = i % 10;
    switch (round)
    {
      case 0:
        ROUND( 0 );
      break;
      case 1:
        ROUND( 1 );
      break;
      case 2:
        ROUND( 2 );
      break;
      case 3:
        ROUND( 3 );
      break;
      case 4:
        ROUND( 4 );
      break;
      case 5:
        ROUND( 5 );
      break;
      case 6:
        ROUND( 6 );
      break;
      case 7:
        ROUND( 7 );
      break;
      case 8:
        ROUND( 8 );
      break;
      case 9:
        ROUND( 9 );
      break;
    default:
      break;
    }

  }
  row1l = _mm_xor_si128( row3l, row1l );
  row1h = _mm_xor_si128( row3h, row1h );
  STOREU( &h[0], _mm_xor_si128( LOADU( &h[0] ), row1l ) );
  STOREU( &h[2], _mm_xor_si128( LOADU( &h[2] ), row1h ) );
  row2l = _mm_xor_si128( row4l, row2l );
  row2h = _mm_xor_si128( row4h, row2h );
  STOREU( &h[4], _mm_xor_si128( LOADU( &h[4] ), row2l ) );
  STOREU( &h[6], _mm_xor_si128( LOADU( &h[6] ), row2h ) );

  for( i = 0; i < 8; ++i )
    store64( out + sizeof( h[i] ) * i, h[i] );
}


void blake2bf_eip152(uint8_t out[BLAKE2B_OUTBYTES], const uint8_t payload[EIP152_PAYLOAD_LEN])
{
  union {
    uint32_t u32;
    uint8_t arr[4];
  } r;
  uint64_t rounds;
  uint64_t h[EIP152_H_LEN];
  uint8_t m[EIP152_M_LEN];
  uint64_t t[EIP152_T_LEN];
  uint64_t f[2] = {0};
  size_t i;

  memcpy(r.arr, payload + EIP152_ROUNDS_OFFSET, EIP152_ROUNDS_LEN);
  rounds = be32toh(r.u32);

  for( i = 0; i < 8; i++) {
    h[i] = load64(payload + EIP152_H_OFFSET + i * sizeof(uint64_t));
  }

  memcpy(m, payload + EIP152_M_OFFSET, EIP152_M_LEN);

  t[0] = load64(payload + EIP152_T_OFFSET);
  t[1] = load64(payload + EIP152_T_OFFSET + sizeof(uint64_t));

  if(payload[EIP152_F_OFFSET] != 0) {
    f[0] = (uint64_t)-1;
  }

  blake2b_compress(out, rounds, h, m, t, f);
}
