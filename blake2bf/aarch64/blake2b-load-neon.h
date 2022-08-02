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

#ifndef BLAKE2B_LOAD_NEON_H
#define BLAKE2B_LOAD_NEON_H

#define LOAD_MSG_0_1(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m1)); \
  b1 = vcombine_u64(vget_low_u64(m2), vget_low_u64(m3));

#define LOAD_MSG_0_2(b0, b1) \
  b0 = vcombine_u64(vget_high_u64(m0), vget_high_u64(m1)); \
  b1 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m3));

#define LOAD_MSG_0_3(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m5)); \
  b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m7));

#define LOAD_MSG_0_4(b0, b1) \
  b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m5)); \
  b1 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m7));

#define LOAD_MSG_1_1(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m2)); \
  b1 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m6));

#define LOAD_MSG_1_2(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m5), vget_low_u64(m4)); \
  b1 = vextq_u64(m7, m3, 1);

#define LOAD_MSG_1_3(b0, b1) \
  b0 = vextq_u64(m0, m0, 1); \
  b1 = vcombine_u64(vget_high_u64(m5), vget_high_u64(m2));

#define LOAD_MSG_1_4(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m1)); \
  b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1));

#define LOAD_MSG_2_1(b0, b1) \
  b0 = vextq_u64(m5, m6, 1); \
  b1 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m7));

#define LOAD_MSG_2_2(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m0)); \
  b1 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m6));

#define LOAD_MSG_2_3(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m5), vget_high_u64(m1)); \
  b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m4));

#define LOAD_MSG_2_4(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m3)); \
  b1 = vextq_u64(m0, m2, 1);

#define LOAD_MSG_3_1(b0, b1) \
  b0 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)); \
  b1 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m5));

#define LOAD_MSG_3_2(b0, b1) \
  b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m0)); \
  b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m7));

#define LOAD_MSG_3_3(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m2)); \
  b1 = vcombine_u64(vget_low_u64(m2), vget_high_u64(m7));

#define LOAD_MSG_3_4(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m3), vget_low_u64(m5)); \
  b1 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m4));

#define LOAD_MSG_4_1(b0, b1) \
  b0 = vcombine_u64(vget_high_u64(m4), vget_high_u64(m2)); \
  b1 = vcombine_u64(vget_low_u64(m1), vget_low_u64(m5));

#define LOAD_MSG_4_2(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m0), vget_high_u64(m3)); \
  b1 = vcombine_u64(vget_low_u64(m2), vget_high_u64(m7));

#define LOAD_MSG_4_3(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m7), vget_high_u64(m5)); \
  b1 = vcombine_u64(vget_low_u64(m3), vget_high_u64(m1));

#define LOAD_MSG_4_4(b0, b1) \
  b0 = vextq_u64(m0, m6, 1); \
  b1 = vcombine_u64(vget_low_u64(m4), vget_high_u64(m6));

#define LOAD_MSG_5_1(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m1), vget_low_u64(m3)); \
  b1 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m4));

#define LOAD_MSG_5_2(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m5)); \
  b1 = vcombine_u64(vget_high_u64(m5), vget_high_u64(m1));

#define LOAD_MSG_5_3(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m2), vget_high_u64(m3)); \
  b1 = vcombine_u64(vget_high_u64(m7), vget_high_u64(m0));

#define LOAD_MSG_5_4(b0, b1) \
  b0 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m2)); \
  b1 = vcombine_u64(vget_low_u64(m7), vget_high_u64(m4));

#define LOAD_MSG_6_1(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m6), vget_high_u64(m0)); \
  b1 = vcombine_u64(vget_low_u64(m7), vget_low_u64(m2));

#define LOAD_MSG_6_2(b0, b1) \
  b0 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m7)); \
  b1 = vextq_u64(m6, m5, 1);

#define LOAD_MSG_6_3(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m3)); \
  b1 = vextq_u64(m4, m4, 1);

#define LOAD_MSG_6_4(b0, b1) \
  b0 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m1)); \
  b1 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m5));

#define LOAD_MSG_7_1(b0, b1) \
  b0 = vcombine_u64(vget_high_u64(m6), vget_high_u64(m3)); \
  b1 = vcombine_u64(vget_low_u64(m6), vget_high_u64(m1));

#define LOAD_MSG_7_2(b0, b1) \
  b0 = vextq_u64(m5, m7, 1); \
  b1 = vcombine_u64(vget_high_u64(m0), vget_high_u64(m4));

#define LOAD_MSG_7_3(b0, b1) \
  b0 = vcombine_u64(vget_high_u64(m2), vget_high_u64(m7)); \
  b1 = vcombine_u64(vget_low_u64(m4), vget_low_u64(m1));

#define LOAD_MSG_7_4(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m0), vget_low_u64(m2)); \
  b1 = vcombine_u64(vget_low_u64(m3), vget_low_u64(m5));

#define LOAD_MSG_8_1(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m3), vget_low_u64(m7)); \
  b1 = vextq_u64(m5, m0, 1);

#define LOAD_MSG_8_2(b0, b1) \
  b0 = vcombine_u64(vget_high_u64(m7), vget_high_u64(m4)); \
  b1 = vextq_u64(m1, m4, 1);

#define LOAD_MSG_8_3(b0, b1) \
  b0 = m6; \
  b1 = vextq_u64(m0, m5, 1);

#define LOAD_MSG_8_4(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m1), vget_high_u64(m3)); \
  b1 = m2;

#define LOAD_MSG_9_1(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m5), vget_low_u64(m4)); \
  b1 = vcombine_u64(vget_high_u64(m3), vget_high_u64(m0));

#define LOAD_MSG_9_2(b0, b1) \
  b0 = vcombine_u64(vget_low_u64(m1), vget_low_u64(m2)); \
  b1 = vcombine_u64(vget_low_u64(m3), vget_high_u64(m2));

#define LOAD_MSG_9_3(b0, b1) \
  b0 = vcombine_u64(vget_high_u64(m7), vget_high_u64(m4)); \
  b1 = vcombine_u64(vget_high_u64(m1), vget_high_u64(m6));

#define LOAD_MSG_9_4(b0, b1) \
  b0 = vextq_u64(m5, m7, 1); \
  b1 = vcombine_u64(vget_low_u64(m6), vget_low_u64(m0));

#endif
