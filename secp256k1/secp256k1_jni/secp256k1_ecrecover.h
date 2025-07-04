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
 * @param message_hash the 32-byte message hash that was signed
 * @param signature the 64-byte compact signature (r || s)
 * @param recovery_id the recovery ID (0, 1, 2, or 3)
 * @param output_buffer the output buffer to write the recovered public key (65 bytes uncompressed)
 * @return 1 if recovery was successful, 0 otherwise
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