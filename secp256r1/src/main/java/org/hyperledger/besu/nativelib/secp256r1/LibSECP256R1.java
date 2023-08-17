package org.hyperledger.besu.nativelib.secp256r1;

import org.hyperledger.besu.nativelib.secp256r1.besuNativeEC.BesuNativeEC;
import org.hyperledger.besu.nativelib.secp256r1.besuNativeEC.KeyRecoveryResult.KeyRecoveryResultByValue;
import org.hyperledger.besu.nativelib.secp256r1.besuNativeEC.SignResult.SignResultByValue;
import org.hyperledger.besu.nativelib.secp256r1.besuNativeEC.VerifyResult.VerifyResultByValue;

import java.util.Arrays;

public class LibSECP256R1 {
    static int VERIFICATION_SUCCESS = 1;
    static int PUBLIC_KEY_LENGTH = 64;
    static int CURVE_BYTE_LENGTH = 32;

    public byte[] keyRecovery(final byte[] dataHash, final byte[] signatureR, final byte[] signatureS,
                              final int signatureV) throws IllegalArgumentException {
        final KeyRecoveryResultByValue result = BesuNativeEC.INSTANCE.p256_key_recovery(
                dataHash,
                dataHash.length,
                convertToNativeRepresentation(signatureR),
                convertToNativeRepresentation(signatureS),
                signatureV
        );

        String errorMessage = (new String(result.error_message)).trim();

        if (!errorMessage.isEmpty()) {
            throw new IllegalArgumentException(errorMessage);
        }

        return Arrays.copyOf(result.public_key, PUBLIC_KEY_LENGTH);
    }

    public Signature sign(byte[] dataHash, byte[] privateKey, byte[] publicKey) throws IllegalArgumentException {
        final SignResultByValue result = BesuNativeEC.INSTANCE.p256_sign(
                dataHash, dataHash.length, privateKey, publicKey);

        String errorMessage = (new String(result.error_message)).trim();

        if (!errorMessage.isEmpty()) {
            throw new IllegalArgumentException(errorMessage);
        }

        return new Signature(
                convertToNonNegativeRepresentation(result.signature_r),
                convertToNonNegativeRepresentation(result.signature_s),
                result.signature_v
        );
    }

    public boolean verify(final byte[] dataHash, final byte[] signatureR, final byte[] signatureS,
                          final byte[] publicKey) throws IllegalArgumentException {
        final VerifyResultByValue result = BesuNativeEC.INSTANCE.p256_verify(
                dataHash,
                dataHash.length,
                convertToNativeRepresentation(signatureR),
                convertToNativeRepresentation(signatureS),
                publicKey);

        if (result.verified < 0) {
            String errorMessage = (new String(result.error_message)).trim();
            throw new IllegalArgumentException(errorMessage);
        }

        return result.verified == VERIFICATION_SUCCESS;
    }

    /**
     * @param signature Signature that has been created by the native library
     * @return non negative representation of the provided signature
     *
     * Signatures can only be positive numbers. The library provides them as big-endian byte
     * array. But it does not take into consideration if those can be interpreted as negative or
     * not, because it is implied that a signature can never be negative. As other classes, like
     * BigInteger, can interpret byte arrays as negative values, the signature needs to be
     * converted in a non-negative number.
     *
     * In big-endian if the first bit is set to 1 it is considered negative. We test for it
     * and if it is indeed negative the array is shifted to the right and the first byte set to 0.
     */
    private byte[] convertToNonNegativeRepresentation(final byte[] signature) {
        // check if the first bit is set, which means it would be considered negative
        if ((signature[0] & 0x80) != 0x80) {
            // The returned array has 66 elements, we are only interested in the first 32 ones
            return Arrays.copyOf(signature, CURVE_BYTE_LENGTH);
        }

        byte[] nonNegativeSignature = new byte[CURVE_BYTE_LENGTH + 1];
        nonNegativeSignature[0] = 0;
        // copy signature to nonNegativeSignature, shifting it to the right
        System.arraycopy(signature, 0, nonNegativeSignature, 1, CURVE_BYTE_LENGTH);

        return nonNegativeSignature;
    }

    /**
     * @param signature Signature that will be passed as parameter to the native library
     * @return representation of the provided signature that the native library expects
     *
     * This function converts the big-endian byte array back to the representation which is expected by the native
     * library. It will shift the array to the left if the number would be interpreted as negative. See
     * function convertToNonNegativeRepresentation for more details. In case the first byte in the native representation
     * was zero, it will shift it to the right.
     */
    private byte[] convertToNativeRepresentation(final byte[] signature) {
        // signature was converted to non-native representation and needs to be shifted to the left
        if (isConvertedSignature(signature)) {
            byte[] nativeSignature = new byte[CURVE_BYTE_LENGTH];

            // copy signature to nativeSignature, shifting it one to the left
            System.arraycopy(signature, 1, nativeSignature, 0, signature.length - 1);

            return nativeSignature;
        }

        // the first bytes in the native representation were 0, but in the Java representation this is ignored.
        // the signature needs to be shifted to the right for the native representation
        if (signature.length < CURVE_BYTE_LENGTH) {
            byte[] nativeSignature = new byte[CURVE_BYTE_LENGTH];

            // copy signature to nativeSignature, shifting it to the right
            System.arraycopy(signature, 0, nativeSignature, CURVE_BYTE_LENGTH - signature.length, signature.length);

            return nativeSignature;
        }

        if (signature.length != CURVE_BYTE_LENGTH) {
            throw new IllegalArgumentException("Signature must be " + CURVE_BYTE_LENGTH + " bytes long, but has " + signature.length + " bytes.");
        }

        // the signature is equal to its native representation and can be returned as it is.
        return signature;
    }

    private boolean isConvertedSignature(byte[] signature) {
        // if the first byte is 0 and the first bit of the second byte is 1, the signature was converted to a
        // non-negative representation and needs to be converted back to its native representation
        return (signature.length == CURVE_BYTE_LENGTH + 1) && (signature[0] == 0) && ((signature[1] & 0x80) == 0x80);
    }
}
