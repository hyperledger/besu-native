package org.hyperledger.besu.nativelib.constantine;

public class LibConstantineEIP196 {
    static {
        System.loadLibrary("constantine");
    }

    public native int ctt_eth_evm_bn254_g1add(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public native int ctt_eth_evm_bn254_g1mul(byte[] r, int r_len, byte[] inputs, int inputs_len);
    public native int ctt_eth_evm_bn254_pairingCheck(byte[] r, int r_len, byte[] inputs, int inputs_len);

    public static void main(String[] args) {
        LibConstantineEIP196 constInstance = new LibConstantineEIP196();

        byte[] r = new byte[64];
        byte[] inputs = new byte[128];
        int status = constInstance.ctt_eth_evm_bn254_g1add(r, r.length, inputs, inputs.length);
        System.out.println("ctt_eth_evm_bn254_g1add status: " + status + ", result: " + bytesToHex(r));

        r = new byte[64];
        inputs = new byte[96];
        status = constInstance.ctt_eth_evm_bn254_g1mul(r, r.length, inputs, inputs.length);
        System.out.println("ctt_eth_evm_bn254_g1mul status: " + status + ", result: " + bytesToHex(r));

        r = new byte[32];
        inputs = new byte[256];
        status = constInstance.ctt_eth_evm_bn254_pairingCheck(r, r.length, inputs, inputs.length);
        System.out.println("ctt_eth_evm_bn254_pairingCheck status: " + status + ", result: " + bytesToHex(r));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}