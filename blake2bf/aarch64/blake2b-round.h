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

#ifndef BLAKE2B_ROUND_H
#define BLAKE2B_ROUND_H

#define vrorq_n_u64_32(x) vreinterpretq_u64_u32(vrev64q_u32(vreinterpretq_u32_u64((x))))

#define vrorq_n_u64_24(x) vcombine_u64( \
      vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_low_u64(x)), vreinterpret_u8_u64(vget_low_u64(x)), 3)), \
      vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_high_u64(x)), vreinterpret_u8_u64(vget_high_u64(x)), 3)))

#define vrorq_n_u64_16(x) vcombine_u64( \
      vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_low_u64(x)), vreinterpret_u8_u64(vget_low_u64(x)), 2)), \
      vreinterpret_u64_u8(vext_u8(vreinterpret_u8_u64(vget_high_u64(x)), vreinterpret_u8_u64(vget_high_u64(x)), 2)))

#define vrorq_n_u64_63(x) veorq_u64(vaddq_u64(x, x), vshrq_n_u64(x, 63))

#define G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
  row1l = vaddq_u64(vaddq_u64(row1l, b0), row2l); \
  row1h = vaddq_u64(vaddq_u64(row1h, b1), row2h); \
  row4l = veorq_u64(row4l, row1l); row4h = veorq_u64(row4h, row1h); \
  row4l = vrorq_n_u64_32(row4l); row4h = vrorq_n_u64_32(row4h); \
  row3l = vaddq_u64(row3l, row4l); row3h = vaddq_u64(row3h, row4h); \
  row2l = veorq_u64(row2l, row3l); row2h = veorq_u64(row2h, row3h); \
  row2l = vrorq_n_u64_24(row2l); row2h = vrorq_n_u64_24(row2h);

#define G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1) \
  row1l = vaddq_u64(vaddq_u64(row1l, b0), row2l); \
  row1h = vaddq_u64(vaddq_u64(row1h, b1), row2h); \
  row4l = veorq_u64(row4l, row1l); row4h = veorq_u64(row4h, row1h); \
  row4l = vrorq_n_u64_16(row4l); row4h = vrorq_n_u64_16(row4h); \
  row3l = vaddq_u64(row3l, row4l); row3h = vaddq_u64(row3h, row4h); \
  row2l = veorq_u64(row2l, row3l); row2h = veorq_u64(row2h, row3h); \
  row2l = vrorq_n_u64_63(row2l); row2h = vrorq_n_u64_63(row2h);

#define DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
    t0 = vextq_u64(row2l, row2h, 1); \
    t1 = vextq_u64(row2h, row2l, 1); \
    row2l = t0; row2h = t1; t0 = row3l;  row3l = row3h; row3h = t0; \
    t0 = vextq_u64(row4h, row4l, 1); t1 = vextq_u64(row4l, row4h, 1); \
    row4l = t0; row4h = t1;

#define UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h) \
    t0 = vextq_u64(row2h, row2l, 1); \
    t1 = vextq_u64(row2l, row2h, 1); \
    row2l = t0; row2h = t1; t0 = row3l; row3l = row3h; row3h = t0; \
    t0 = vextq_u64(row4l, row4h, 1); t1 = vextq_u64(row4h, row4l, 1); \
    row4l = t0; row4h = t1;

#include "blake2b-load-neon.h"

#define ROUND(r) \
  LOAD_MSG_ ##r ##_1(b0, b1); \
  G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
  LOAD_MSG_ ##r ##_2(b0, b1); \
  G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
  DIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h); \
  LOAD_MSG_ ##r ##_3(b0, b1); \
  G1(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
  LOAD_MSG_ ##r ##_4(b0, b1); \
  G2(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h,b0,b1); \
  UNDIAGONALIZE(row1l,row2l,row3l,row4l,row1h,row2h,row3h,row4h);

#endif
