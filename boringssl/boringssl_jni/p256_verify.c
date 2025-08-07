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

#define RETURN_INVALID(msg) do { snprintf(error_message_buf, error_message_buf_len, "%s", msg); ret = 1; goto cleanup; } while (0)
#define RETURN_ERROR(msg) do { snprintf(error_message_buf, error_message_buf_len, "%s", msg); ret = 2; goto cleanup; } while (0)


int p256_verify(
    const char data_hash[], int data_hash_length,
    const char signature_r[], int signature_r_length,
    const char signature_s[], int signature_s_length,
    const char public_key_data[], int public_key_data_length,
    char error_message_buf[], int error_message_buf_len) {

  EC_KEY *ec_key = NULL;
  EC_POINT *point = NULL;
  ECDSA_SIG *sig = NULL;
  BIGNUM *r = NULL, *s = NULL;
  const EC_GROUP *group = NULL;
  BN_CTX *ctx = NULL;
  int ret = 0;

  if (!data_hash || !signature_r || !signature_s || !public_key_data) {
    RETURN_ERROR("null input");
  }

  // Validate input array sizes
  if (data_hash_length != 32) {
    RETURN_ERROR("data_hash must be exactly 32 bytes");
  }
  if (signature_r_length != 32) {
    RETURN_INVALID("signature_r must be exactly 32 bytes");
  }
  if (signature_s_length != 32) {
    RETURN_INVALID("signature_s must be exactly 32 bytes");
  }
  if (public_key_data_length != 65) {
    RETURN_INVALID("public_key_data must be exactly 65 bytes");
  }

  if ((unsigned char)public_key_data[0] != 0x04) {
    RETURN_INVALID("public key must start with 0x04");
  }

  ctx = BN_CTX_new();
  if (!ctx) {
    RETURN_ERROR("BN_CTX allocation failed");
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

  if (!EC_POINT_oct2point(group, point, (const uint8_t *)public_key_data, P256_KEY_LEN, ctx)) {
    RETURN_INVALID("failed to parse public key point");
  }

  if (!EC_POINT_is_on_curve(group, point, ctx)) {
    RETURN_INVALID("public key not on curve");
  }

  if (EC_KEY_set_public_key(ec_key, point) != 1) {
    RETURN_ERROR("failed to assign public key");
  }

  r = BN_bin2bn((const uint8_t *)signature_r, P256_COORD_LEN, NULL);
  s = BN_bin2bn((const uint8_t *)signature_s, P256_COORD_LEN, NULL);
  if (!r || !s) {
    RETURN_ERROR("failed to parse r or s");
  }

  sig = ECDSA_SIG_new();
  if (!sig || ECDSA_SIG_set0(sig, r, s) != 1) {
    RETURN_ERROR("failed to create signature");
  }

  // ownership transferred to sig
  r = NULL;
  s = NULL;

  int verify_status = ECDSA_do_verify((const uint8_t *)data_hash, data_hash_length, sig, ec_key);
  
  if (verify_status == 1) {
    error_message_buf[0] = '\0';  // No error message
    ret = 0;
  } else if (verify_status == 0) {
    snprintf(error_message_buf, error_message_buf_len, "%s", "signature verification failed");
    ret = 1;
  } else {
    snprintf(error_message_buf, error_message_buf_len, "%s", "internal error during signature verification");
    ret = 2;
  }

cleanup:
  BN_CTX_free(ctx);
  if (group) EC_GROUP_free((EC_GROUP *)group);
  if (ec_key) EC_KEY_free(ec_key);
  if (point) EC_POINT_free(point);
  if (sig) ECDSA_SIG_free(sig);
  if (r) BN_free(r);
  if (s) BN_free(s);
  
  return ret;
}
