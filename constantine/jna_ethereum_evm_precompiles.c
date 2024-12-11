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
int ipa_commit(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ipa_commit(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int ipa_prove(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ipa_prove(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int ipa_verify(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ipa_verify(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int ipa_multi_prove(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ipa_multi_prove(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int ipa_multi_verify(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) ipa_multi_verify(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int ipa_deserialize(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) deserialize(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int ipa_serialize(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) serialize(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int ipa_map_to_scalar_field(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) mapToScalarField(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int ipa_batch_map_to_scalar_field(byte* r, int r_len, const byte* inputs, int inputs_len) {
    return (int) batchMapToScalarField(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}