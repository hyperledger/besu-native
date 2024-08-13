package org.hyperledger.besu.nativelib.constantine;

public class LibConstantineEIP196 {
    static {
        System.loadLibrary("constantineeip196");
    }

    public native int ctt_eth_evm_bn254_g1add(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public native int ctt_eth_evm_bn254_g1mul(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public native int ctt_eth_evm_bn254_pairingCheck(byte[] r, int r_len, byte[] inputs, int inputs_len);

    public static void loadNativeLibrary() {
        System.loadLibrary("constantineeip196");
    }

    public byte[] add(byte[] inputs) {
        byte[] result = new byte[64];
        int status = ctt_eth_evm_bn254_g1add(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("ctt_eth_evm_bn254_g1add failed with status: " + status);
        }
        return result;
    }

    public byte[] mul(byte[] inputs) {
        byte[] result = new byte[64];
        int status = ctt_eth_evm_bn254_g1mul(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("ctt_eth_evm_bn254_g1mul failed with status: " + status);
        }
        return result;
    }

    public byte[] pairingCheck(byte[] inputs) {
        byte[] result = new byte[32];
        int status = ctt_eth_evm_bn254_pairingCheck(result, result.length, inputs, inputs.length);
        if (status != 0) {
            throw new RuntimeException("ctt_eth_evm_bn254_pairingCheck failed with status: " + status);
        }
        return result;
    }
}