package org.hyperledger.besu.nativelib.boringssl;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.util.Arrays;
import java.util.Collection;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hyperledger.besu.nativelib.boringssl.BoringSSLPrecompiles.ecrecover;

@RunWith(Parameterized.class)
public class SecP256R1ParameterizedTest {

    private final String hash;
    private final String sig;
    private final int recoveryId;
    private final String pubkey;
    private final boolean success;

    public SecP256R1ParameterizedTest(String hash, String sig, int recoveryId, String pubkey, boolean success) {
        this.hash = hash;
        this.sig = sig;
        this.recoveryId = recoveryId;
        this.pubkey = pubkey;
        this.success = success;
    }

    private byte[] hexToBytes(String hex) {
        if (hex == null) {
            return null;
        }
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }

    @Parameterized.Parameters
    public static Collection<Object[]> data() {
        return Arrays.asList(new Object[][]{
                // Valid case
                {"4b68ab3847feda7d6c62c1fbcbe54368316afb042c81868a5972936d3735d04b", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 0, "0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", true},
                // Invalid recovery id
                {"4b68ab3847feda7d6c62c1fbcbe54368316afb042c81868a5972936d3735d04b", "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8", 4, null, false},
                // Invalid signature
                {"4b68ab3847feda7d6c62c1fbcbe54368316afb042c81868a5972936d3735d04b", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 0, null, false},
        });
    }

    @Test
    public void testECRecover() {
        byte[] hashBytes = hexToBytes(hash);
        byte[] sigBytes = hexToBytes(sig);
        byte[] pubkeyBytes = hexToBytes(pubkey);

        BoringSSLPrecompiles.EcrecoverResult result = ecrecover(hashBytes, sigBytes, recoveryId);

        if (success) {
            assertThat(result.error).isEmpty();
            assertThat(result.publicKey).isPresent();
            assertThat(result.publicKey.get()).isEqualTo(pubkeyBytes);
        } else {
            assertThat(result.error).isPresent();
            assertThat(result.publicKey).isNotPresent();
        }
    }
}
