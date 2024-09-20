package org.hyperledger.besu.nativelib.constantine;

import com.sun.jna.Native;

public class LibConstantineEIP196 {
    public static final boolean ENABLED;

    static {
        boolean enabled;
        try {
            Native.register(LibConstantineEIP196.class, "constantinebindings");
            enabled = true;
        } catch (final Throwable t) {
            t.printStackTrace();
            enabled = false;
        }
        ENABLED = enabled;
    }

    public static native int bn254_g1add(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public static native int bn254_g1mul(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public static native int bn254_pairingCheck(byte[] r, int r_len, byte[] inputs, int inputs_len);

    public static byte[] add(byte[] inputs) {
        byte[] result = new byte[64];
        int status = bn254_g1add(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("ctt_eth_evm_bn254_g1add failed with status: " + status);
        }
        return result;
    }

    public static byte[] mul(byte[] inputs) {
        byte[] result = new byte[64];
        int status = bn254_g1mul(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("ctt_eth_evm_bn254_g1mul failed with status: " + status);
        }
        return result;
    }

    public static byte[] pairingCheck(byte[] inputs) {
        byte[] result = new byte[32];
        int status = bn254_pairingCheck(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("ctt_eth_evm_bn254_pairingCheck failed with status: " + status);
        }
        return result;
    }
}
