package org.hyperledger.besu.nativelib.constantine;

import com.sun.jna.Native;

public class LibConstantineEIP196 {

    public static final int EIP196_PREALLOCATE_FOR_RESULT_BYTES = 128;
    public static final int EIP196_PREALLOCATE_FOR_ERROR_BYTES = 256;

    static {
        Native.register(LibConstantineEIP196.class, "constantine_eip196");
    }

    public static native int eth_evm_bn254_g1add(byte[] output, int outputLen, byte[] input, int inputLen);

    public static native int eth_evm_bn254_g1mul(byte[] output, int outputLen, byte[] input, int inputLen);

    public static native int eth_evm_bn254_ecpairingcheck(byte[] output, int outputLen, byte[] input, int inputLen);

}