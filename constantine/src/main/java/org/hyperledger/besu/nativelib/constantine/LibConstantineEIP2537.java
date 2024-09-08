package org.hyperledger.besu.nativelib.constantine;

import com.sun.jna.Native;

public class LibConstantineEIP2537 {
    public static final boolean ENABLED;

    static {
        boolean enabled;
        try {
            Native.register(LibConstantineEIP2537.class, "constantinebindings");
            enabled = true;
        } catch (final Throwable t) {
            t.printStackTrace();
            enabled = false;
        }
        ENABLED = enabled;
    }

    public static native int bls12381_g1add(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public static native int bls12381_g2add(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public static native int bls12381_g1mul(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public static native int bls12381_g2mul(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public static native int bls12381_g1msm(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public static native int bls12381_g2msm(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public static native int bls12381_pairingcheck(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public static native int bls12381_map_fp_to_g1(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public static native int bls12381_map_fp2_to_g2(byte[] r, int r_len, byte[] inputs, int inputs_len);

    public static byte[] g1add(byte[] inputs) {
        byte[] result = new byte[96];
        int status = bls12381_g1add(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("eth_evm_bls12381_g1add failed with status: " + status);
        }
        return result;
    }

    public static byte[] g2add(byte[] inputs) {
        byte[] result = new byte[192];
        int status = bls12381_g2add(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("eth_evm_bls12381_g2add failed with status: " + status);
        }
        return result;
    }

    public static byte[] g1mul(byte[] inputs) {
        byte[] result = new byte[96];
        int status = bls12381_g1mul(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("eth_evm_bls12381_g1mul failed with status: " + status);
        }
        return result;
    }

    public static byte[] g2mul(byte[] inputs) {
        byte[] result = new byte[192];
        int status = bls12381_g2mul(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("eth_evm_bls12381_g2mul failed with status: " + status);
        }
        return result;
    }

    public static byte[] g1msm(byte[] inputs) {
        byte[] result = new byte[96];
        int status = bls12381_g1msm(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("eth_evm_bls12381_g1msm failed with status: " + status);
        }
        return result;
    }

    public static byte[] g2msm(byte[] inputs) {
        byte[] result = new byte[192];
        int status = bls12381_g2msm(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("eth_evm_bls12381_g2msm failed with status: " + status);
        }
        return result;
    }

    public static byte[] pairingCheck(byte[] inputs) {
        byte[] result = new byte[32];
        int status = bls12381_pairingcheck(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("eth_evm_bls12381_pairingcheck failed with status: " + status);
        }
        return result;
    }

    public static byte[] mapFpToG1(byte[] inputs) {
        byte[] result = new byte[96];
        int status = bls12381_map_fp_to_g1(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("eth_evm_bls12381_map_fp_to_g1 failed with status: " + status);
        }
        return result;
    }

    public static byte[] mapFp2ToG2(byte[] inputs) {
        byte[] result = new byte[192];
        int status = bls12381_map_fp2_to_g2(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("eth_evm_bls12381_map_fp2_to_g2 failed with status: " + status);
        }
        return result;
    }

    public static void main(String[] args) {
        byte[] inputs = new byte[192];  // G1Add inputs for BLS12-381 should be 192 bytes

        byte[] result = LibConstantineEIP2537.g1add(inputs);
    }
}