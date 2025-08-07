/*
 * Copyright contributors to Besu.
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
 * SPDX-License-Identifier: Apache-2.0
 *
 */
#ifndef ECRECOVER_H
#define ECRECOVER_H

#ifdef __cplusplus
extern "C" {
#endif

// Recovers a P-256 public key from a signature and message hash.
//
// All inputs are raw big-endian byte arrays. This function assumes standard sizes:
// - message_hash: exactly 32 bytes
// - signature: exactly 64 bytes (r=32bytes + s=32bytes)
// - output_buffer: exactly 65 bytes
//
// Size validation is performed internally for security in JNA environments.
//
// Returns:
//   0 - success, public key written to output_buffer
//   1 - invalid input parameters or signature verification failed  
//   2 - system error (memory allocation, curve operations failed)
//
// If an error occurs, a descriptive message is written to error_message_buf.
// On success, error_message_buf is set to an empty string.
int ecrecover_r1(
    const unsigned char message_hash[], int message_hash_len,
    const unsigned char signature[], int signature_len,
    int recovery_id,
    unsigned char output_buffer[], int output_buffer_len,
    char error_message_buf[], int error_message_buf_len);

#ifdef __cplusplus
}
#endif

#endif // ECRECOVER_H
