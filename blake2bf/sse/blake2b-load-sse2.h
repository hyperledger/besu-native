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

#ifndef BLAKE2B_LOAD_SSE2_H
#define BLAKE2B_LOAD_SSE2_H

#define LOAD_MSG_0_1(b0, b1) b0 = _mm_set_epi64x(m2, m0); b1 = _mm_set_epi64x(m6, m4)
#define LOAD_MSG_0_2(b0, b1) b0 = _mm_set_epi64x(m3, m1); b1 = _mm_set_epi64x(m7, m5)
#define LOAD_MSG_0_3(b0, b1) b0 = _mm_set_epi64x(m10, m8); b1 = _mm_set_epi64x(m14, m12)
#define LOAD_MSG_0_4(b0, b1) b0 = _mm_set_epi64x(m11, m9); b1 = _mm_set_epi64x(m15, m13)
#define LOAD_MSG_1_1(b0, b1) b0 = _mm_set_epi64x(m4, m14); b1 = _mm_set_epi64x(m13, m9)
#define LOAD_MSG_1_2(b0, b1) b0 = _mm_set_epi64x(m8, m10); b1 = _mm_set_epi64x(m6, m15)
#define LOAD_MSG_1_3(b0, b1) b0 = _mm_set_epi64x(m0, m1); b1 = _mm_set_epi64x(m5, m11)
#define LOAD_MSG_1_4(b0, b1) b0 = _mm_set_epi64x(m2, m12); b1 = _mm_set_epi64x(m3, m7)
#define LOAD_MSG_2_1(b0, b1) b0 = _mm_set_epi64x(m12, m11); b1 = _mm_set_epi64x(m15, m5)
#define LOAD_MSG_2_2(b0, b1) b0 = _mm_set_epi64x(m0, m8); b1 = _mm_set_epi64x(m13, m2)
#define LOAD_MSG_2_3(b0, b1) b0 = _mm_set_epi64x(m3, m10); b1 = _mm_set_epi64x(m9, m7)
#define LOAD_MSG_2_4(b0, b1) b0 = _mm_set_epi64x(m6, m14); b1 = _mm_set_epi64x(m4, m1)
#define LOAD_MSG_3_1(b0, b1) b0 = _mm_set_epi64x(m3, m7); b1 = _mm_set_epi64x(m11, m13)
#define LOAD_MSG_3_2(b0, b1) b0 = _mm_set_epi64x(m1, m9); b1 = _mm_set_epi64x(m14, m12)
#define LOAD_MSG_3_3(b0, b1) b0 = _mm_set_epi64x(m5, m2); b1 = _mm_set_epi64x(m15, m4)
#define LOAD_MSG_3_4(b0, b1) b0 = _mm_set_epi64x(m10, m6); b1 = _mm_set_epi64x(m8, m0)
#define LOAD_MSG_4_1(b0, b1) b0 = _mm_set_epi64x(m5, m9); b1 = _mm_set_epi64x(m10, m2)
#define LOAD_MSG_4_2(b0, b1) b0 = _mm_set_epi64x(m7, m0); b1 = _mm_set_epi64x(m15, m4)
#define LOAD_MSG_4_3(b0, b1) b0 = _mm_set_epi64x(m11, m14); b1 = _mm_set_epi64x(m3, m6)
#define LOAD_MSG_4_4(b0, b1) b0 = _mm_set_epi64x(m12, m1); b1 = _mm_set_epi64x(m13, m8)
#define LOAD_MSG_5_1(b0, b1) b0 = _mm_set_epi64x(m6, m2); b1 = _mm_set_epi64x(m8, m0)
#define LOAD_MSG_5_2(b0, b1) b0 = _mm_set_epi64x(m10, m12); b1 = _mm_set_epi64x(m3, m11)
#define LOAD_MSG_5_3(b0, b1) b0 = _mm_set_epi64x(m7, m4); b1 = _mm_set_epi64x(m1, m15)
#define LOAD_MSG_5_4(b0, b1) b0 = _mm_set_epi64x(m5, m13); b1 = _mm_set_epi64x(m9, m14)
#define LOAD_MSG_6_1(b0, b1) b0 = _mm_set_epi64x(m1, m12); b1 = _mm_set_epi64x(m4, m14)
#define LOAD_MSG_6_2(b0, b1) b0 = _mm_set_epi64x(m15, m5); b1 = _mm_set_epi64x(m10, m13)
#define LOAD_MSG_6_3(b0, b1) b0 = _mm_set_epi64x(m6, m0); b1 = _mm_set_epi64x(m8, m9)
#define LOAD_MSG_6_4(b0, b1) b0 = _mm_set_epi64x(m3, m7); b1 = _mm_set_epi64x(m11, m2)
#define LOAD_MSG_7_1(b0, b1) b0 = _mm_set_epi64x(m7, m13); b1 = _mm_set_epi64x(m3, m12)
#define LOAD_MSG_7_2(b0, b1) b0 = _mm_set_epi64x(m14, m11); b1 = _mm_set_epi64x(m9, m1)
#define LOAD_MSG_7_3(b0, b1) b0 = _mm_set_epi64x(m15, m5); b1 = _mm_set_epi64x(m2, m8)
#define LOAD_MSG_7_4(b0, b1) b0 = _mm_set_epi64x(m4, m0); b1 = _mm_set_epi64x(m10, m6)
#define LOAD_MSG_8_1(b0, b1) b0 = _mm_set_epi64x(m14, m6); b1 = _mm_set_epi64x(m0, m11)
#define LOAD_MSG_8_2(b0, b1) b0 = _mm_set_epi64x(m9, m15); b1 = _mm_set_epi64x(m8, m3)
#define LOAD_MSG_8_3(b0, b1) b0 = _mm_set_epi64x(m13, m12); b1 = _mm_set_epi64x(m10, m1)
#define LOAD_MSG_8_4(b0, b1) b0 = _mm_set_epi64x(m7, m2); b1 = _mm_set_epi64x(m5, m4)
#define LOAD_MSG_9_1(b0, b1) b0 = _mm_set_epi64x(m8, m10); b1 = _mm_set_epi64x(m1, m7)
#define LOAD_MSG_9_2(b0, b1) b0 = _mm_set_epi64x(m4, m2); b1 = _mm_set_epi64x(m5, m6)
#define LOAD_MSG_9_3(b0, b1) b0 = _mm_set_epi64x(m9, m15); b1 = _mm_set_epi64x(m13, m3)
#define LOAD_MSG_9_4(b0, b1) b0 = _mm_set_epi64x(m14, m11); b1 = _mm_set_epi64x(m0, m12)

#endif
