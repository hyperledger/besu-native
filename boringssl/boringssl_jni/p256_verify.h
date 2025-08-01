#ifndef P256_VERIFY_H
#define P256_VERIFY_H

#ifdef __cplusplus
extern "C" {
#endif

// Verifies a P-256 signature (r, s) on data_hash using an uncompressed public key.
// All inputs are raw big-endian byte arrays.
// Writes a null-terminated diagnostic message (if any) into error_message_buf (must be at least error_message_buf_len bytes).
// Returns: 0 = OK, 1 = INVALID, 2 = ERROR
int p256_verify(
    const char data_hash[], int data_hash_length,
    const char signature_r[], int signature_r_length,
    const char signature_s[], int signature_s_length,
    const char public_key_data[], int public_key_data_length,
    char error_message_buf[], int error_message_buf_len);

#ifdef __cplusplus
}
#endif

#endif // P256_VERIFY_H
