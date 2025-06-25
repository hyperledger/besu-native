#ifndef P256_VERIFY_H
#define P256_VERIFY_H

#ifdef __cplusplus
extern "C" {
#endif

// Return struct for verification
typedef struct {
    int status;           // 0 = OK, 1 = INVALID, 2 = ERROR
    const char *message;  // NULL if OK; otherwise error string
} verify_result_ex;

// Verifies a P-256 signature (r, s) on data_hash using an uncompressed public key.
// All inputs are raw big-endian byte arrays.
// Returns a verify_result_ex struct with status and diagnostic message.
verify_result_ex p256_verify(
    const char data_hash[], int data_hash_length,
    const char signature_r[], const char signature_s[],
    const char public_key_data[]);

#ifdef __cplusplus
}
#endif

#endif // P256_VERIFY_H
