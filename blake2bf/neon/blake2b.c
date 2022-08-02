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
#include <endian.h>
#include <arm_neon.h>

#include "blake2.h"
#include "blake2-impl.h"

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
  const uint64x2_t m0 = vreinterpretq_u64_u8(vld1q_u8(&block[  0]));
  const uint64x2_t m1 = vreinterpretq_u64_u8(vld1q_u8(&block[ 16]));
  const uint64x2_t m2 = vreinterpretq_u64_u8(vld1q_u8(&block[ 32]));
  const uint64x2_t m3 = vreinterpretq_u64_u8(vld1q_u8(&block[ 48]));
  const uint64x2_t m4 = vreinterpretq_u64_u8(vld1q_u8(&block[ 64]));
  const uint64x2_t m5 = vreinterpretq_u64_u8(vld1q_u8(&block[ 80]));
  const uint64x2_t m6 = vreinterpretq_u64_u8(vld1q_u8(&block[ 96]));
  const uint64x2_t m7 = vreinterpretq_u64_u8(vld1q_u8(&block[112]));

  uint64x2_t row1l, row1h, row2l, row2h;
  uint64x2_t row3l, row3h, row4l, row4h;
  uint64x2_t t0, t1, b0, b1;

  const uint64x2_t h0 = row1l = vld1q_u64(&h[0]);
  const uint64x2_t h1 = row1h = vld1q_u64(&h[2]);
  const uint64x2_t h2 = row2l = vld1q_u64(&h[4]);
  const uint64x2_t h3 = row2h = vld1q_u64(&h[6]);

  size_t i, round;

  row3l = vld1q_u64(&blake2b_IV[0]);
  row3h = vld1q_u64(&blake2b_IV[2]);
  row4l = veorq_u64(vld1q_u64(&blake2b_IV[4]), vld1q_u64(&t[0]));
  row4h = veorq_u64(vld1q_u64(&blake2b_IV[6]), vld1q_u64(&f[0]));

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

  vst1q_u64(&h[0], veorq_u64(h0, veorq_u64(row1l, row3l)));
  vst1q_u64(&h[2], veorq_u64(h1, veorq_u64(row1h, row3h)));
  vst1q_u64(&h[4], veorq_u64(h2, veorq_u64(row2l, row4l)));
  vst1q_u64(&h[6], veorq_u64(h3, veorq_u64(row2h, row4h)));

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
