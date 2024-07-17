#include <jni.h>
#include "ethereum_evm_precompiles.h"
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

JNIEXPORT jint JNICALL Java_org_hyperledger_besu_nativelib_constantine_LibConstantineEIP196_ctt_1eth_1evm_1bn254_1g1add(JNIEnv *env, jobject obj, jbyteArray jr, jint r_len, jbyteArray jinputs, jint inputs_len) {
    jbyte *r = (*env)->GetByteArrayElements(env, jr, NULL);
    jbyte *inputs = (*env)->GetByteArrayElements(env, jinputs, NULL);

    ctt_evm_status status = ctt_eth_evm_bn254_g1add((byte *)r, (ptrdiff_t)r_len, (const byte *)inputs, (ptrdiff_t)inputs_len);

    (*env)->ReleaseByteArrayElements(env, jr, r, 0);
    (*env)->ReleaseByteArrayElements(env, jinputs, inputs, 0);

    return (jint)status;
}

JNIEXPORT jint JNICALL Java_org_hyperledger_besu_nativelib_constantine_LibConstantineEIP196_ctt_1eth_1evm_1bn254_1g1mul(JNIEnv *env, jobject obj, jbyteArray jr, jint r_len, jbyteArray jinputs, jint inputs_len) {
    jbyte *r = (*env)->GetByteArrayElements(env, jr, NULL);
    jbyte *inputs = (*env)->GetByteArrayElements(env, jinputs, NULL);

    ctt_evm_status status = ctt_eth_evm_bn254_g1mul((byte *)r, (ptrdiff_t)r_len, (const byte *)inputs, (ptrdiff_t)inputs_len);

    (*env)->ReleaseByteArrayElements(env, jr, r, 0);
    (*env)->ReleaseByteArrayElements(env, jinputs, inputs, 0);

    return (jint)status;
}

JNIEXPORT jint JNICALL Java_org_hyperledger_besu_nativelib_constantine_LibConstantineEIP196_ctt_1eth_1evm_1bn254_1pairingCheck(JNIEnv *env, jobject obj, jbyteArray jr, jint r_len, jbyteArray jinputs, jint inputs_len) {
    jbyte *r = (*env)->GetByteArrayElements(env, jr, NULL);
    jbyte *inputs = (*env)->GetByteArrayElements(env, jinputs, NULL);

    ctt_evm_status status = ctt_eth_evm_bn254_ecpairingcheck((byte *)r, (ptrdiff_t)r_len, (const byte *)inputs, (ptrdiff_t)inputs_len);

    (*env)->ReleaseByteArrayElements(env, jr, r, 0);
    (*env)->ReleaseByteArrayElements(env, jinputs, inputs, 0);

    return (jint)status;
}