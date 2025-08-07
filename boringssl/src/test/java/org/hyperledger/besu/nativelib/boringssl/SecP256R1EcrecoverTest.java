/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
package org.hyperledger.besu.nativelib.boringssl;

import org.apache.tuweni.bytes.Bytes;
import org.junit.Before;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hyperledger.besu.nativelib.boringssl.BoringSSLPrecompiles.ecrecover;

public class SecP256R1EcrecoverTest {
    
    private final Bytes data = Bytes.fromHexString("c35e2f092553c55772926bdbe87c9796827d17024dbb9233a545366e2e5987dd344deb72df987144b8c6c43bc41b654b94cc856e16b96d7a821c8ec039b503e3d86728c494a967d83011a0e090b5d54cd47f4e366c0912bc808fbb2ea96efac88fb3ebec9342738e225f7c7c2b011ce375b56621a20642b4d36e060db4524af1");
    private final Bytes signatureR = Bytes.fromHexString("976d3a4e9d23326dc0baa9fa560b7c4e53f42864f508483a6473b6a11079b2db");
    private final Bytes signatureS = Bytes.fromHexString("1b766e9ceb71ba6c01dcd46e0af462cd4cfa652ae5017d4555b8eeefe36e1932");
    private final Bytes publicKey = Bytes.fromHexString("e266ddfdc12668db30d4ca3e8f7749432c416044f2d2b8c10bf3d4012aeffa8abfa86404a2e9ffe67d47c587ef7a97a7f456b863b4d02cfc6928973ab5b1cb39");
    private final int signatureV = 0;
    
    private byte[] dataHash;
    
    @Before
    public void setUp() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        dataHash = digest.digest(data.toArrayUnsafe());
    }

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
        // Combine r and s into 64-byte signature
        byte[] sig = new byte[64];
        System.arraycopy(signatureR.toArrayUnsafe(), 0, sig, 0, 32);
        System.arraycopy(signatureS.toArrayUnsafe(), 0, sig, 32, 32);
        
        // Expected uncompressed public key (0x04 prefix + coordinates)
        byte[] expectedPubkey = new byte[65];
        expectedPubkey[0] = 0x04;
        System.arraycopy(publicKey.toArrayUnsafe(), 0, expectedPubkey, 1, 64);

        BoringSSLPrecompiles.ECRecoverResult result = ecrecover(dataHash, sig, signatureV);

        assertThat(result.status()).isEqualTo(0);
        assertThat(result.error()).isEmpty();
        assertThat(result.publicKey()).isPresent();
        assertThat(result.publicKey().get()).isEqualTo(expectedPubkey);
    }
}
