package org.hyperledger.besu.nativelib.secp256r1;

import org.hyperledger.besu.nativelib.secp256r1.besuNativeEC.BesuNativeEC;
import org.hyperledger.besu.nativelib.secp256r1.besuNativeEC.KeyRecoveryResult;
import org.hyperledger.besu.nativelib.secp256r1.besuNativeEC.SignResult;
import org.hyperledger.besu.nativelib.secp256r1.besuNativeEC.VerifyResult;

import java.util.Arrays;

public class LibSECP256R1 {
    static int VERIFICATION_SUCCESS = 1;
    static int PUBLIC_KEY_LENGTH = 64;
    static int CURVE_BYTE_LENGTH = 32;

    public byte[] keyRecovery(final byte[] dataHash, final byte[] signatureR, final byte[] signatureS,
                              final int signatureV) throws IllegalArgumentException {
        final KeyRecoveryResult.ByValue result = BesuNativeEC.INSTANCE.p256_key_recovery(
                dataHash,
                dataHash.length,
                signatureR,
                signatureS,
                signatureV
        );

        String errorMessage = (new String(result.error_message)).trim();

        if (!errorMessage.isEmpty()) {
            throw new IllegalArgumentException(errorMessage);
        }

        return Arrays.copyOf(result.public_key, PUBLIC_KEY_LENGTH);
    }

    public Signature sign(byte[] dataHash, byte[] privateKey, byte[] publicKey) throws IllegalArgumentException {
        final SignResult.ByValue result = BesuNativeEC.INSTANCE.p256_sign(
                dataHash, dataHash.length, privateKey, publicKey);

        String errorMessage = (new String(result.error_message)).trim();

        if (!errorMessage.isEmpty()) {
            throw new IllegalArgumentException(errorMessage);
        }

        return new Signature(
                Arrays.copyOf(result.signature_r, CURVE_BYTE_LENGTH),
                Arrays.copyOf(result.signature_s, CURVE_BYTE_LENGTH),
                result.signature_v
        );
    }

    public boolean verify(final byte[] dataHash, final byte[] signatureR, final byte[] signatureS,
                          final byte[] publicKey) throws IllegalArgumentException {
        final VerifyResult.ByValue result = BesuNativeEC.INSTANCE.p256_verify(
                dataHash, dataHash.length, signatureR, signatureS, publicKey);

        if (result.verified < 0) {
            String errorMessage = (new String(result.error_message)).trim();
            throw new IllegalArgumentException(errorMessage);
        }

        return result.verified == VERIFICATION_SUCCESS;
    }
}
