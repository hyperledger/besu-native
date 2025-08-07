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
#include "ecrecover.h"

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

int ecrecover_r1(
    const unsigned char message_hash[], int message_hash_len,
    const unsigned char signature[], int signature_len,
    int recovery_id,
    unsigned char output_buffer[], int output_buffer_len,
    char error_message_buf[], int error_message_buf_len) {

    BN_CTX *ctx = NULL;
    BIGNUM *r = NULL, *s = NULL, *e = NULL;
    EC_GROUP *group = NULL;
    BIGNUM *r_inv = NULL;
    EC_POINT *R = NULL;
    BIGNUM *u1 = NULL, *u2 = NULL, *e_r_inv = NULL;
    EC_POINT *Q = NULL;
    int ret = 0;

    if (message_hash == NULL || signature == NULL || output_buffer == NULL) {
        RETURN_INVALID("null input parameters");
    }

    // Validate input array sizes
    if (message_hash_len != 32) {
        RETURN_INVALID("message_hash must be exactly 32 bytes");
    }
    if (signature_len != 64) {
        RETURN_INVALID("signature must be exactly 64 bytes");
    }
    if (output_buffer_len < 65) {
        RETURN_INVALID("output_buffer must be at least 65 bytes");
    }

    // restrict recovery_id to uncompressed point types
    if (recovery_id < 0 || recovery_id > 1) {
        RETURN_INVALID("invalid recovery_id, must be 0 or 1");
    }

    ctx = BN_CTX_new();
    if (!ctx) {
        RETURN_ERROR("BN_CTX allocation failed");
    }

    BN_CTX_start(ctx);
    r = BN_CTX_get(ctx);
    s = BN_CTX_get(ctx);
    e = BN_CTX_get(ctx);
    r_inv = BN_CTX_get(ctx);
    if (!r || !s || !e || !r_inv) {
        RETURN_ERROR("failed to get BIGNUMs from context");
    }

    if (!BN_bin2bn(signature, P256_COORD_LEN, r)) {
        RETURN_ERROR("failed to parse signature r component");
    }
    if (!BN_bin2bn(signature + P256_COORD_LEN, P256_COORD_LEN, s)) {
        RETURN_ERROR("failed to parse signature s component");
    }
    if (!BN_bin2bn(message_hash, 32, e)) {
        RETURN_ERROR("failed to parse message hash");
    }

    group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) {
        RETURN_ERROR("EC_GROUP allocation failed");
    }
    const BIGNUM *order = EC_GROUP_get0_order(group);

    if (!BN_mod_inverse(r_inv, r, order, ctx)) {
        RETURN_INVALID("failed to compute modular inverse of r");
    }

    R = EC_POINT_new(group);
    if (!R) {
        RETURN_ERROR("EC_POINT allocation failed");
    }
    if (!EC_POINT_set_compressed_coordinates_GFp(group, R, r, recovery_id & 1, ctx)) {
        RETURN_INVALID("failed to recover point R from signature");
    }

    u1 = BN_CTX_get(ctx);
    u2 = BN_CTX_get(ctx);
    e_r_inv = BN_CTX_get(ctx);
    if (!u1 || !u2 || !e_r_inv) {
        RETURN_ERROR("BIGNUM allocation failed");
    }

    BN_mod_mul(e_r_inv, e, r_inv, order, ctx); // e * r_inv mod n

    if (BN_is_zero(e_r_inv)) {
        BN_zero(u1);
    } else {
        BN_sub(u1, order, e_r_inv); // order - (e * r_inv mod n)
    }

    BN_mod_mul(u2, s, r_inv, order, ctx);

    Q = EC_POINT_new(group);
    if (!Q) {
        RETURN_ERROR("EC_POINT allocation failed for public key");
    }
    if (!EC_POINT_mul(group, Q, u1, R, u2, ctx)) {
        RETURN_INVALID("failed to compute public key point");
    }

    if (EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED, output_buffer, P256_KEY_LEN, ctx) != P256_KEY_LEN) {
        RETURN_ERROR("failed to serialize recovered public key");
    }

    // Success case
    error_message_buf[0] = '\0';

cleanup:
    if (ctx) {
        BN_CTX_end(ctx);
        BN_CTX_free(ctx);
    }
    if (group) EC_GROUP_free(group);
    if (R) EC_POINT_free(R);
    if (Q) EC_POINT_free(Q);

    return ret;
}
