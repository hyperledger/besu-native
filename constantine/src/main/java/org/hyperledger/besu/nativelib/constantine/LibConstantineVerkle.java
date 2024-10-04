package org.hyperledger.besu.nativelib.constantine;

import com.sun.jna.Native;

public class LibConstantineVerkle {
    public static final boolean ENABLED;

    static {
        boolean enabled;
        try {
            Native.register(LibConstantineVerkle.class, "verkle");
            enabled = true;
        } catch (final Throwable t) {
            t.printStackTrace();
            enabled = false;
        }
        ENABLED = enabled;
    }

    // Declare native methods
    public static native int ipa_commit(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public static native int ipa_prove(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public static native int ipa_verify(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public static native int ipa_multi_prove(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public static native int ipa_multi_verify(byte[] r, int r_len, byte[] inputs, int inputs_len);

    // Add utility methods for easier access in Java
    public static byte[] commit(byte[] inputs) {
        byte[] result = new byte[128];
        int status = ipa_commit(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("ipa_commit failed with status: " + status);
        }
        return result;
    }

    public static byte[] prove(byte[] inputs) {
        byte[] result = new byte[128];
        int status = ipa_prove(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("ipa_prove failed with status: " + status);
        }
        return result;
    }

    public static byte[] verify(byte[] inputs) {
        byte[] result = new byte[128];
        int status = ipa_verify(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("ipa_verify failed with status: " + status);
        }
        return result;
    }

    public static byte[] multiProve(byte[] inputs) {
        byte[] result = new byte[128];
        int status = ipa_multi_prove(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("ipa_multi_prove failed with status: " + status);
        }
        return result;
    }

    public static byte[] multiVerify(byte[] inputs) {
        byte[] result = new byte[128];
        int status = ipa_multi_verify(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("ipa_multi_verify failed with status: " + status);
        }
        return result;
    }
}
