package org.hyperledger.besu.nativelib.boringssl;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hyperledger.besu.nativelib.boringssl.BoringSSLPrecompiles.ecrecover;

public class SecP256R1Test {

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    @Test
    public void testECRecover() {
        byte[] hash = hexToBytes("4b68ab3847feda7d6c62c1fbcbe54368316afb042c81868a5972936d3735d04b");
        byte[] sig = hexToBytes("79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");
        byte[] pubkey = hexToBytes("0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8");

        BoringSSLPrecompiles.EcrecoverResult result = ecrecover(hash, sig, 0);

        assertThat(result.error).isEmpty();
        assertThat(result.publicKey).isPresent();
        assertThat(result.publicKey.get()).isEqualTo(pubkey);
    }
}
