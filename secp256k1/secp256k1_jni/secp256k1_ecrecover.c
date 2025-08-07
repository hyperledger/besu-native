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
#include "secp256k1_ecrecover.h"
#include <secp256k1.h>
#include <secp256k1_recovery.h>
#include <string.h>

// Create a shared context for secp256k1 operations
static secp256k1_context* ctx = NULL;

// Initialize the context once
static void ensure_context() {
    if (ctx == NULL) {
        ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
        if (ctx == NULL) {
            return; // Failed to create context
        }
    }
}

// Internal implementation with size validation
static int secp256k1_ecrecover_jni_impl(
    const unsigned char message_hash[], int message_hash_len,
    const unsigned char signature[], int signature_len,
    int recovery_id,
    unsigned char output_buffer[], int output_buffer_len) {
    
    // Ensure we have a valid context
    ensure_context();
    if (ctx == NULL) {
        return 1; // Context creation failed
    }

    // Validate inputs
    if (message_hash == NULL || signature == NULL || output_buffer == NULL) {
        return 1;
    }

    // Validate input array sizes
    if (message_hash_len != 32) {
        return 1; // message_hash must be exactly 32 bytes
    }
    if (signature_len != 64) {
        return 1; // signature must be exactly 64 bytes
    }
    if (output_buffer_len < 65) {
        return 1; // output_buffer must be at least 65 bytes
    }

    // restrict recovery id to uncompressed point types
    if (recovery_id < 0 || recovery_id > 1) {
        return 1;
    }

    secp256k1_ecdsa_recoverable_signature recoverable_sig;
    secp256k1_pubkey pubkey;
    size_t output_len = 65;

    // Step 1: Parse the signature with recovery ID
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            ctx, &recoverable_sig, signature, recovery_id) != 1) {
        return 1; // Failed to parse signature
    }

    // Step 2: Recover the public key from the signature
    if (secp256k1_ecdsa_recover(ctx, &pubkey, &recoverable_sig, message_hash) != 1) {
        return 1; // Failed to recover public key
    }

    // Step 3: Serialize the public key in uncompressed format
    if (secp256k1_ec_pubkey_serialize(
            ctx, output_buffer, &output_len, &pubkey, SECP256K1_EC_UNCOMPRESSED) != 1) {
        return 1; // Failed to serialize public key
    }

    // Verify we got the expected length
    if (output_len != 65) {
        return 1; // Unexpected output length
    }

    return 0; // Success
}

// Public API with backward compatibility (assumes standard sizes)
int secp256k1_ecrecover_jni(
    const unsigned char message_hash[32],
    const unsigned char signature[64],
    int recovery_id,
    unsigned char output_buffer[65]) {
    
    return secp256k1_ecrecover_jni_impl(
        message_hash, 32,
        signature, 64,
        recovery_id,
        output_buffer, 65);
}

// Cleanup function (called when library is unloaded)
__attribute__((destructor))
static void cleanup_context() {
    if (ctx != NULL) {
        secp256k1_context_destroy(ctx);
        ctx = NULL;
    }
}
