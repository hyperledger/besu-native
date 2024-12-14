#include <constantine.h>
#include <stdio.h>

void printByteArray(const char* label, const byte* array, size_t len) {
    printf("%s: [", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", array[i]);
        if (i < len - 1) {
            printf(", ");
        }
    }
    printf("]\n");
}

// BN254 functions
int bn254_g1add(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ctt_eth_evm_bn254_g1add(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int bn254_g1mul(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ctt_eth_evm_bn254_g1mul(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int bn254_pairingCheck(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ctt_eth_evm_bn254_ecpairingcheck(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

// BLS12-381 functions
int bls12381_g1add(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ctt_eth_evm_bls12381_g1add(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int bls12381_g2add(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ctt_eth_evm_bls12381_g2add(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int bls12381_g1mul(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ctt_eth_evm_bls12381_g1mul(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int bls12381_g2mul(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ctt_eth_evm_bls12381_g2mul(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int bls12381_g1msm(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ctt_eth_evm_bls12381_g1msm(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int bls12381_g2msm(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ctt_eth_evm_bls12381_g2msm(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int bls12381_pairingCheck(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ctt_eth_evm_bls12381_pairingcheck(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int bls12381_mapFpToG1(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ctt_eth_evm_bls12381_map_fp_to_g1(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int bls12381_mapFp2ToG2(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ctt_eth_evm_bls12381_map_fp2_to_g2(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

// Verkle functions
int ipa_commit_aff(const ctt_eth_verkle_ipa_polynomial_eval_crs *crs, banderwagon_ec_aff res, const ctt_eth_verkle_ipa_polynomial_eval_poly *poly) {
    ctt_eth_verkle_ipa_commit_aff(crs, res, poly);
}

int ipa_commit_prj(const ctt_eth_verkle_ipa_polynomial_eval_crs *crs, banderwagon_ec_prj res, const ctt_eth_verkle_ipa_polynomial_eval_poly *poly) {
    ctt_eth_verkle_ipa_commit_prj(crs, res, poly);
}

int ipa_prove(const ctt_eth_verkle_ipa_polynomial_eval_crs *crs, const ctt_eth_verkle_ipa_poly_eval_linear_domain *domain, ctt_eth_verkle_ipa_transcript *transcript, banderwagon_fr *eval_at_challenge, ctt_eth_verkle_ipa_proof_aff *proof, const ctt_eth_verkle_ipa_polynomial_eval_poly *poly, const banderwagon_ec_aff *commitment, const banderwagon_fr *opening_challenge) {
    ctt_eth_verkle_ipa_prove(crs, domain, transcript, eval_at_challenge, proof, poly, commitment, opening_challenge);
}

int ipa_verify(const ctt_eth_verkle_ipa_polynomial_eval_crs *crs, const ctt_eth_verkle_ipa_poly_eval_linear_domain *domain, ctt_eth_verkle_ipa_transcript *transcript, const banderwagon_ec_aff *commitment, const banderwagon_fr *opening_challenge, banderwagon_fr *eval_at_challenge, const ctt_eth_verkle_ipa_proof_aff *proof) {
    ctt_eth_verkle_ipa_verify(crs, domain, transcript, commitment, opening_challenge, eval_at_challenge, proof);
}

int ipa_multi_prove(const ctt_eth_verkle_ipa_polynomial_eval_crs *crs, const ctt_eth_verkle_ipa_poly_eval_linear_domain *domain, ctt_eth_verkle_ipa_transcript *transcript, ctt_eth_verkle_ipa_multi_proof_aff *proof, const ctt_eth_verkle_ipa_polynomial_eval_poly polys[], size_t poly_len, const banderwagon_ec_aff commitments[], size_t commitment_len, const uint64_t opening_challenges_in_domain[], size_t opening_challenges_len) {
    ctt_eth_verkle_ipa_multi_prove(crs, domain, transcript, proof, polys, poly_len, commitments, commitment_len, opening_challenges_in_domain, opening_challenges_len);
}

int ipa_multi_verify(const ctt_eth_verkle_ipa_polynomial_eval_crs *crs, const ctt_eth_verkle_ipa_poly_eval_linear_domain *domain, ctt_eth_verkle_ipa_transcript *transcript, const banderwagon_ec_aff commitments[], size_t commitments_len, const uint64_t opening_challenges_in_domain[], size_t opening_challenges_len, const banderwagon_fr evals_at_challenge[], size_t evals_len, const ctt_eth_verkle_ipa_multi_proof_aff *proof) {
    ctt_eth_verkle_ipa_multi_verify(crs, domain, transcript, commitments, commitments_len, opening_challenges_in_domain, opening_challenges_len, evals_at_challenge, evals_len, proof);
}

int ipa_deserialize_aff(ctt_eth_verkle_ipa_proof_aff *src, const ctt_eth_verkle_ipa_proof_bytes *dst) {
    return (int) ctt_eth_verkle_ipa_deserialize_aff(src, dst);
}

int ipa_deserialize_prj(ctt_eth_verkle_ipa_proof_prj *src, const ctt_eth_verkle_ipa_proof_bytes *dst) {
    return (int) ctt_eth_verkle_ipa_deserialize_prj(src, dst);
}

int ipa_serialize_aff(ctt_eth_verkle_ipa_proof_bytes *dst, const ctt_eth_verkle_ipa_proof_aff *src) {
    return (int) ctt_eth_verkle_ipa_serialize_aff(dst, src);
}

int ipa_serialize_prj(ctt_eth_verkle_ipa_proof_bytes *dst, const ctt_eth_verkle_ipa_proof_prj *src) {
    return (int) ctt_eth_verkle_ipa_serialize_prj(dst, src);
}

int ipa_map_to_scalar_field_aff(banderwagon_fr *res, const banderwagon_ec_aff *p) {
    return (int) ctt_eth_verkle_ipa_map_to_scalar_field_aff(res, p);
}

int ipa_map_to_scalar_field_prj(banderwagon_fr *res, const banderwagon_ec_prj *p) {
    return (int) ctt_eth_verkle_ipa_map_to_scalar_field_prj(res, p);
}

int ipa_batch_map_to_scalar_field_aff(banderwagon_fr res[], const banderwagon_ec_aff points[], size_t len) {
    return (int) ctt_eth_verkle_ipa_batch_map_to_scalar_field_aff(res, points, len);
}

int ipa_batch_map_to_scalar_field_prj(banderwagon_fr res[], const banderwagon_ec_prj points[], size_t len) {
    return (int) ctt_eth_verkle_ipa_batch_map_to_scalar_field_prj(res, points, len);
}