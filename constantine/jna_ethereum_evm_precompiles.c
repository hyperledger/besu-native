#include "jna_ethereum_evm_precompiles.h"
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

int bn254_g1add(byte* r, int r_len, const byte* inputs, int inputs_len) {
    // Call the original function
    return (int) ctt_eth_evm_bn254_g1add(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int bn254_g1mul(byte* r, int r_len, const byte* inputs, int inputs_len) {
    // Call the original function
    return (int) ctt_eth_evm_bn254_g1mul(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

int bn254_pairingCheck(byte* r, int r_len, const byte* inputs, int inputs_len) {
    // Call the original function
    return (int) ctt_eth_evm_bn254_ecpairingcheck(r, (ptrdiff_t)r_len, inputs, (ptrdiff_t)inputs_len);
}

