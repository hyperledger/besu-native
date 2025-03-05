package org.hyperledger.besu.nativelib.constantine;

import com.sun.jna.Native;

public class LibConstantineKeccak256 {
    public static final boolean ENABLED;

    static {
        boolean enabled;
        try {
            Native.register(LibConstantineKeccak256.class, "constantinebindings");
            enabled = true;
        } catch (final Throwable t) {
            t.printStackTrace();
            enabled = false;
        }
        ENABLED = enabled;
    }

    public static native int keccak256(byte[] output, byte[] input, int input_len);

    public static byte[] keccak256(byte[] input) {
        byte[] output = new byte[32];
        keccak256(output, input, input.length);
        return output;
    }

}
