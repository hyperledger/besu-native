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
#ifndef BLAKE2_H
#define BLAKE2_H

#include <stddef.h>
#include <stdint.h>

#if defined(_MSC_VER)
#define BLAKE2_PACKED(x) __pragma(pack(push, 1)) x __pragma(pack(pop))
#else
#define BLAKE2_PACKED(x) x __attribute__((packed))
#endif

#if defined(__cplusplus)
extern "C" {
#endif

  enum blake2b_constant
  {
    BLAKE2B_BLOCKBYTES = 128,
    BLAKE2B_OUTBYTES   = 64
  };

  enum eip152_constant
  {
    EIP152_PAYLOAD_LEN=213,
    EIP152_ROUNDS_OFFSET=0,
    EIP152_ROUNDS_LEN=4,
    EIP152_H_OFFSET = EIP152_ROUNDS_OFFSET + EIP152_ROUNDS_LEN,
    EIP152_H_LEN = 64,
    EIP152_M_OFFSET = EIP152_H_OFFSET + EIP152_H_LEN,
    EIP152_M_LEN = 128,
    EIP152_T_OFFSET = EIP152_M_OFFSET + EIP152_M_LEN,
    EIP152_T_LEN = 16,
    EIP152_F_OFFSET = EIP152_T_OFFSET + EIP152_T_LEN,
    EIP152_F_LEN = 1
  };

  void blake2bf_eip152(uint8_t out[BLAKE2B_OUTBYTES], const uint8_t payload[EIP152_PAYLOAD_LEN]);

#if defined(__cplusplus)
}
#endif

#endif
