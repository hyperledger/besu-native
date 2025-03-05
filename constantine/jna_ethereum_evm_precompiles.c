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


void keccak256(byte* result, byte* message, int message_len) {
    ctt_keccak256_hash(result, message, (ptrdiff_t)message_len,0);
}