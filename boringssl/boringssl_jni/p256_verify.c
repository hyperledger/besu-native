#include "p256_verify.h"
#include <openssl/bn.h>


#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/mem.h>
#include <string.h>


static void print_hex(const char *label, const uint8_t *data, size_t len) {
    fprintf(stderr, "%s [%zu]: ", label, len);
    for (size_t i = 0; i < len; ++i) {
        fprintf(stderr, "%02x", data[i]);
    }
    fprintf(stderr, "\n");
}

verify_result p256_verify_malleable_signature(
    const char data_hash[], int data_hash_length,
    const char signature_r[], const char signature_s[],
    const char public_key_data[]) {

//    fprintf(stderr, "=== p256_verify_malleable_signature ===\n");
//
//    print_hex("data_hash", (const uint8_t *)data_hash, data_hash_length);
//    print_hex("signature_r", (const uint8_t *)signature_r, 32);
//    print_hex("signature_s", (const uint8_t *)signature_s, 32);
//    print_hex("public_key", (const uint8_t *)public_key_data, 64);
//    fflush(stderr);
    verify_result result = VERIFY_ERROR;

    EC_KEY *ec_key = NULL;
    ECDSA_SIG *sig = NULL;

    // Constants: P-256 key and signature sizes
    const size_t key_len = 65;       // uncompressed 0x04 + 32-byte X + 32-byte Y
    const size_t coord_len = 32;

    if (!data_hash || !signature_r || !signature_s || !public_key_data || data_hash_length != 32) {
//        fprintf(stderr, "something wrong with params.\n");
//        fflush(stderr);
        return VERIFY_ERROR;
    }

    // Construct EC_KEY from uncompressed public key bytes
    const EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1);
    if (!group) {
//        fprintf(stderr, "Failed to get curve by group name.\n");
//        fflush(stderr);
        goto cleanup;
    }

    const BIGNUM *order = EC_GROUP_get0_order(group);
    char *order_str = BN_bn2hex(order);
//    fprintf(stderr, "curve order: %s\n", order_str);
    OPENSSL_free(order_str);

    ec_key = EC_KEY_new();
    if (!ec_key) {
//        fprintf(stderr, "Failed to allocate ec_key.\n");
//        fflush(stderr);
        goto cleanup;
    }

    if (EC_KEY_set_group(ec_key, group) != 1) {
//        fprintf(stderr, "Failed to set group for ec_key.\n");
//        fflush(stderr);
        goto cleanup;
    }

    EC_POINT *point = EC_POINT_new(group);
    if (!point) {
//        fprintf(stderr, "Failed to create ec_point.\n");
//        fflush(stderr);
        goto cleanup;
    }

    // Expect 65-byte uncompressed key: 0x04 || X || Y
    if (public_key_data[0] != 0x04) {
//        fprintf(stderr, "public key byte 0 is not 0x04.\n");
//        fflush(stderr);
        goto cleanup;
    }

    if (!EC_POINT_oct2point(group, point,
                             (const uint8_t *)public_key_data, key_len, NULL)) {
//        fprintf(stderr, "Failed to parse public key point.\n");
//        fflush(stderr);
        EC_POINT_free(point);
        goto cleanup;
    }

    if (EC_KEY_set_public_key(ec_key, point) != 1) {
//        fprintf(stderr, "Failed to set public key point.\n");
//        fflush(stderr);
        EC_POINT_free(point);
        goto cleanup;
    }

    EC_POINT_free(point);

    // Build ECDSA_SIG from r and s
    sig = ECDSA_SIG_new();
    if (!sig) {
//        fprintf(stderr, "Failed to create sig.\n");
//        fflush(stderr);
        goto cleanup;
    }

    BIGNUM *r = BN_bin2bn((const uint8_t *)signature_r, coord_len, NULL);
    BIGNUM *s = BN_bin2bn((const uint8_t *)signature_s, coord_len, NULL);
    if (!r || !s) {
//        fprintf(stderr, "!r or !s.\n");
//        fflush(stderr);
        goto cleanup;
    }
//    if (BN_cmp(r, BN_value_one()) >= 0 || BN_cmp(r, order) < 0) {
//        fprintf(stderr, "failed r check");
//        char *r_str = BN_bn2hex(r);
//        char *order_str = BN_bn2hex(order);
//        fprintf(stderr, "r = %s\n", r_str);
//        fprintf(stderr, "n = %s\n", order_str);
//        OPENSSL_free(r_str);
//        OPENSSL_free(order_str);
//    }


    if (ECDSA_SIG_set0(sig, r, s) != 1) {
//        fprintf(stderr, "Failed to set ecdsa_sig.\n");
//        fflush(stderr);
        BN_free(r); BN_free(s);
        goto cleanup;
    }

    // Perform verification
    int verify_status = ECDSA_do_verify((const uint8_t *)data_hash, data_hash_length, sig, ec_key);
    if (verify_status == 1) {
//        fprintf(stderr, "verify ok, result ok.\n");
//        fflush(stderr);
        result = VERIFY_OK;
    } else if (verify_status == 0) {
//        fprintf(stderr, "verify false, result ok.\n");
//        fflush(stderr);
        result = VERIFY_INVALID;
    } else {
//        fprintf(stderr, "verify false, result error.\n");
//        fflush(stderr);
        result = VERIFY_ERROR;
    }

cleanup:
    ECDSA_SIG_free(sig);
    EC_KEY_free(ec_key);
    return result;
}

