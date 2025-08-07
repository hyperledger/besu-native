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
#ifndef SECP256K1_ECRECOVER_H
#define SECP256K1_ECRECOVER_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Consolidated ECRECOVER operation for optimal performance.
 * 
 * This function combines signature parsing, public key recovery, and serialization
 * into a single native call to minimize overhead.
 * 
 * All inputs are validated for correct sizes to prevent buffer overruns in JNA environments:
 * - message_hash: exactly 32 bytes (validated internally)
 * - signature: exactly 64 bytes (r || s, validated internally)  
 * - output_buffer: exactly 65 bytes (validated internally)
 * 
 * @param message_hash the 32-byte message hash that was signed
 * @param signature the 64-byte compact signature (r || s)
 * @param recovery_id the recovery ID (0, 1)
 * @param output_buffer the output buffer to write the recovered public key (65 bytes uncompressed)
 * @return 0 if recovery was successful, 1 otherwise (including size validation failures)
 */
int secp256k1_ecrecover_jni(
    const unsigned char message_hash[32],
    const unsigned char signature[64],
    int recovery_id,
    unsigned char output_buffer[65]);

#ifdef __cplusplus
}
#endif

#endif // SECP256K1_ECRECOVER_H
