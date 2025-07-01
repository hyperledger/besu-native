#ifndef ECRECOVER_H
#define ECRECOVER_H

#ifdef __cplusplus
extern "C" {
#endif

// Recovers a P-256 public key from a signature and message hash.
//
// All inputs are raw big-endian byte arrays.
//
// returns 1 on success, 0 on failure.
int ecrecover_r1(
    const unsigned char message_hash[32],
    const unsigned char signature[64],
    int recovery_id,
    unsigned char output_buffer[65]);

#ifdef __cplusplus
}
#endif

#endif // ECRECOVER_H
