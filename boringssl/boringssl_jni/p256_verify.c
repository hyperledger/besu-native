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

#define RESULT_OK ((verify_result_ex){0, ""})
#define RESULT_INVALID(msg) ((verify_result_ex){1, msg})
#define RESULT_ERROR(msg) ((verify_result_ex){2, msg})

verify_result_ex p256_verify_malleable_signature(
    const char data_hash[], int data_hash_length,
    const char signature_r[], const char signature_s[],
    const char public_key_data[])
{
    EC_KEY *ec_key = NULL;
    EC_POINT *point = NULL;
    ECDSA_SIG *sig = NULL;
    BIGNUM *r = NULL, *s = NULL, *order = NULL, *half_order = NULL;
    BN_CTX *ctx = NULL;

    if (!data_hash || !signature_r || !signature_s || !public_key_data) {
        return RESULT_ERROR("null input");
    }

    if (data_hash_length != 32) {
        return RESULT_ERROR("invalid hash length");
    }

    if ((unsigned char)public_key_data[0] != 0x04) {
        return RESULT_INVALID("public key must start with 0x04");
    }

    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) return RESULT_ERROR("EC_GROUP allocation failed");

    ec_key = EC_KEY_new();
    if (!ec_key || EC_KEY_set_group(ec_key, group) != 1) return RESULT_ERROR("EC_KEY init failed");

    point = EC_POINT_new(group);
    if (!point) return RESULT_ERROR("EC_POINT allocation failed");

    if (!EC_POINT_oct2point(group, point, (const uint8_t *)public_key_data, P256_KEY_LEN, NULL)) {
        return RESULT_INVALID("failed to parse public key point");
    }

//    if (EC_POINT_is_at_infinity(group, point)) {
//        return RESULT_INVALID("public key is at infinity");
//    }
//
    if (!EC_POINT_is_on_curve(group, point, NULL)) {
        return RESULT_INVALID("public key not on curve");
    }

    if (EC_KEY_set_public_key(ec_key, point) != 1) {
        return RESULT_ERROR("failed to assign public key to EC_KEY");
    }

    r = BN_bin2bn((const uint8_t *)signature_r, P256_COORD_LEN, NULL);
    s = BN_bin2bn((const uint8_t *)signature_s, P256_COORD_LEN, NULL);
    if (!r || !s) return RESULT_ERROR("failed to parse r or s");

    sig = ECDSA_SIG_new();
    if (!sig || ECDSA_SIG_set0(sig, r, s) != 1) {
        BN_free(r);
        BN_free(s);
        return RESULT_ERROR("failed to create ECDSA_SIG");
    }
    r = NULL; // now owned by sig
    s = NULL;

    int verify_status = ECDSA_do_verify((const uint8_t *)data_hash, data_hash_length, sig, ec_key);
    if (verify_status == 1) {
        return RESULT_OK;
    } else if (verify_status == 0) {
        return RESULT_INVALID("signature verification failed");
    } else {
        return RESULT_ERROR("internal error during signature verification");
    }
}
