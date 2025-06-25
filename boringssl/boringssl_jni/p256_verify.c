#include "p256_verify.h"

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <string.h>
#include <stdio.h>

#define P256_KEY_LEN 65
#define P256_COORD_LEN 32

#define RETURN_OK() return 0
#define RETURN_INVALID(msg) do { snprintf(error_message_buf, error_message_buf_len, "%s", msg); return 1; } while (0)
#define RETURN_ERROR(msg) do { snprintf(error_message_buf, error_message_buf_len, "%s", msg); return 2; } while (0)

int p256_verify(
    const char data_hash[], int data_hash_length,
    const char signature_r[], const char signature_s[],
    const char public_key_data[],
    char error_message_buf[], int error_message_buf_len) {

  EC_KEY *ec_key = NULL;
  EC_POINT *point = NULL;
  ECDSA_SIG *sig = NULL;
  BIGNUM *r = NULL, *s = NULL;
  const EC_GROUP *group = NULL;

  if (!data_hash || !signature_r || !signature_s || !public_key_data) {
    RETURN_ERROR("null input");
  }

  if (data_hash_length != 32) {
    RETURN_ERROR("invalid hash length");
  }

  if ((unsigned char)public_key_data[0] != 0x04) {
    RETURN_INVALID("public key must start with 0x04");
  }

  group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
  if (!group) {
    RETURN_ERROR("EC_GROUP allocation failed");
  }

  ec_key = EC_KEY_new();
  if (!ec_key || EC_KEY_set_group(ec_key, group) != 1) {
    RETURN_ERROR("EC_KEY init failed");
  }

  point = EC_POINT_new(group);
  if (!point) {
    RETURN_ERROR("EC_POINT allocation failed");
  }

  if (!EC_POINT_oct2point(group, point, (const uint8_t *)public_key_data, P256_KEY_LEN, NULL)) {
    RETURN_INVALID("failed to parse public key point");
  }

  if (!EC_POINT_is_on_curve(group, point, NULL)) {
    RETURN_INVALID("public key not on curve");
  }

  if (EC_KEY_set_public_key(ec_key, point) != 1) {
    RETURN_ERROR("failed to assign public key to EC_KEY");
  }

  r = BN_bin2bn((const uint8_t *)signature_r, P256_COORD_LEN, NULL);
  s = BN_bin2bn((const uint8_t *)signature_s, P256_COORD_LEN, NULL);
  if (!r || !s) {
    RETURN_ERROR("failed to parse r or s");
  }

  sig = ECDSA_SIG_new();
  if (!sig || ECDSA_SIG_set0(sig, r, s) != 1) {
    BN_free(r);
    BN_free(s);
    RETURN_ERROR("failed to create ECDSA_SIG");
  }

  r = NULL; // ownership transferred to sig
  s = NULL;

  int verify_status = ECDSA_do_verify((const uint8_t *)data_hash, data_hash_length, sig, ec_key);
  if (verify_status == 1) {
    error_message_buf[0] = '\0';  // No error message
    RETURN_OK();
  } else if (verify_status == 0) {
    RETURN_INVALID("signature verification failed");
  } else {
    RETURN_ERROR("internal error during signature verification");
  }
}
