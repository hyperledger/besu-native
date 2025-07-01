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

int ecrecover_r1(
    const unsigned char message_hash[32],
    const unsigned char signature[64],
    int recovery_id,
    unsigned char output_buffer[65]) {

    if (message_hash == NULL || signature == NULL || output_buffer == NULL) {
        return 0;
    }

    if (recovery_id < 0 || recovery_id > 3) {
        return 0;
    }

    BN_CTX *ctx = BN_CTX_new();
    if (!ctx) {
        return 0;
    }

    BIGNUM *r = BN_bin2bn(signature, P256_COORD_LEN, NULL);
    BIGNUM *s = BN_bin2bn(signature + P256_COORD_LEN, P256_COORD_LEN, NULL);
    BIGNUM *e = BN_bin2bn(message_hash, 32, NULL);

    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    const BIGNUM *order = EC_GROUP_get0_order(group);

    BIGNUM *r_inv = BN_mod_inverse(NULL, r, order, ctx);
    if (!r_inv) {
        BN_free(r);
        BN_free(s);
        BN_free(e);
        BN_CTX_free(ctx);
        return 0;
    }

    EC_POINT *R = EC_POINT_new(group);
    if (!EC_POINT_set_compressed_coordinates_GFp(group, R, r, recovery_id & 1, ctx)) {
        BN_free(r);
        BN_free(s);
        BN_free(e);
        BN_free(r_inv);
        EC_POINT_free(R);
        BN_CTX_free(ctx);
        return 0;
    }

    BIGNUM *u1 = BN_new();
    BIGNUM *u2 = BN_new();
    BIGNUM *e_r_inv = BN_new();

    BN_mod_mul(e_r_inv, e, r_inv, order, ctx); // e * r_inv mod n

    if (BN_is_zero(e_r_inv)) {
        BN_zero(u1);
    } else {
        BN_sub(u1, order, e_r_inv); // order - (e * r_inv mod n)
    }
    BN_free(e_r_inv);

    BN_mod_mul(u2, s, r_inv, order, ctx);

    EC_POINT *Q = EC_POINT_new(group);
    if (!EC_POINT_mul(group, Q, u1, R, u2, ctx)) {
        BN_free(r);
        BN_free(s);
        BN_free(e);
        BN_free(r_inv);
        EC_POINT_free(R);
        BN_free(u1);
        BN_free(u2);
        EC_POINT_free(Q);
        BN_CTX_free(ctx);
        return 0;
    }

    if (EC_POINT_point2oct(group, Q, POINT_CONVERSION_UNCOMPRESSED, output_buffer, P256_KEY_LEN, ctx) != P256_KEY_LEN) {
        BN_free(r);
        BN_free(s);
        BN_free(e);
        BN_free(r_inv);
        EC_POINT_free(R);
        BN_free(u1);
        BN_free(u2);
        EC_POINT_free(Q);
        BN_CTX_free(ctx);
        return 0;
    }

    BN_free(r);
    BN_free(s);
    BN_free(e);
    BN_free(r_inv);
    EC_POINT_free(R);
    BN_free(u1);
    BN_free(u2);
    EC_POINT_free(Q);
    BN_CTX_free(ctx);

    return 1;
}
