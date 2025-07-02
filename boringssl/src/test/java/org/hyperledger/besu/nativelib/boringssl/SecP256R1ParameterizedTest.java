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
        // SHA256 hash of test data from LibSECP256R1Test
        String validHash = "9b2db89cb0e8fa3cc7608b4d6cc1dec0114e0b9ff4080bea12b134f489ab2bbc";
        // secp256r1 signature from LibSECP256R1Test  
        String validSig = "976d3a4e9d23326dc0baa9fa560b7c4e53f42864f508483a6473b6a11079b2db1b766e9ceb71ba6c01dcd46e0af462cd4cfa652ae5017d4555b8eeefe36e1932";
        // Expected uncompressed public key (0x04 prefix + coordinates)
        String validPubkey = "04e266ddfdc12668db30d4ca3e8f7749432c416044f2d2b8c10bf3d4012aeffa8abfa86404a2e9ffe67d47c587ef7a97a7f456b863b4d02cfc6928973ab5b1cb39";
        
        return Arrays.asList(new Object[][]{
                // Valid case
                {validHash, validSig, 0, validPubkey, true},
                // Invalid recovery id
                {validHash, validSig, 4, null, false},
                // Invalid signature
                {validHash, "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000", 0, null, false},
        });
    }

    @Test
    public void testECRecover() {
        byte[] hashBytes = hexToBytes(hash);
        byte[] sigBytes = hexToBytes(sig);
        byte[] pubkeyBytes = hexToBytes(pubkey);

        BoringSSLPrecompiles.EcrecoverResult result = ecrecover(hashBytes, sigBytes, recoveryId);

        if (success) {
            assertThat(result.status).isEqualTo(0);
            assertThat(result.error).isEmpty();
            assertThat(result.publicKey).isPresent();
            assertThat(result.publicKey.get()).isEqualTo(pubkeyBytes);
        } else {
            assertThat(result.status).isEqualTo(1);
            assertThat(result.error).isPresent();
            assertThat(result.publicKey).isNotPresent();
        }
    }
}
