#ifndef P256_VERIFY_H
#define P256_VERIFY_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    VERIFY_OK = 0,
    VERIFY_INVALID = 1,
    VERIFY_ERROR = 2
} verify_result;

verify_result p256_verify_malleable_signature(
    const char data_hash[], int data_hash_length,
    const char signature_r[], const char signature_s[],
    const char public_key_data[]);

#ifdef __cplusplus
}
#endif

#endif // P256_VERIFY_H

