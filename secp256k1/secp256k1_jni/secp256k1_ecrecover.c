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

int secp256k1_ecrecover_jni(
    const unsigned char message_hash[32],
    const unsigned char signature[64],
    int recovery_id,
    unsigned char output_buffer[65]) {
    
    // Ensure we have a valid context
    ensure_context();
    if (ctx == NULL) {
        return 0; // Context creation failed
    }

    // Validate inputs
    if (message_hash == NULL || signature == NULL || output_buffer == NULL) {
        return 0;
    }
    
    if (recovery_id < 0 || recovery_id > 3) {
        return 0;
    }

    secp256k1_ecdsa_recoverable_signature recoverable_sig;
    secp256k1_pubkey pubkey;
    size_t output_len = 65;

    // Step 1: Parse the compact signature with recovery ID
    if (secp256k1_ecdsa_recoverable_signature_parse_compact(
            ctx, &recoverable_sig, signature, recovery_id) != 1) {
        return 0; // Failed to parse signature
    }

    // Step 2: Recover the public key from the signature
    if (secp256k1_ecdsa_recover(ctx, &pubkey, &recoverable_sig, message_hash) != 1) {
        return 0; // Failed to recover public key
    }

    // Step 3: Serialize the public key in uncompressed format
    if (secp256k1_ec_pubkey_serialize(
            ctx, output_buffer, &output_len, &pubkey, SECP256K1_EC_UNCOMPRESSED) != 1) {
        return 0; // Failed to serialize public key
    }

    // Verify we got the expected length
    if (output_len != 65) {
        return 0; // Unexpected output length
    }

    return 1; // Success
}

// Cleanup function (called when library is unloaded)
__attribute__((destructor))
static void cleanup_context() {
    if (ctx != NULL) {
        secp256k1_context_destroy(ctx);
        ctx = NULL;
    }
}