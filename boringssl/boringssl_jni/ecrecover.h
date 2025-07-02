#ifndef ECRECOVER_H
#define ECRECOVER_H

#ifdef __cplusplus
extern "C" {
#endif

// Recovers a P-256 public key from a signature and message hash.
//
// All inputs are raw big-endian byte arrays.
//
// Returns:
//   0 - success, public key written to output_buffer
//   1 - invalid input parameters or signature verification failed  
//   2 - system error (memory allocation, curve operations failed)
int ecrecover_r1(
    const unsigned char message_hash[32],
    const unsigned char signature[64],
    int recovery_id,
    unsigned char output_buffer[65]);

#ifdef __cplusplus
}
#endif

#endif // ECRECOVER_H
