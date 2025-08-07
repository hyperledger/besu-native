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
import org.apache.tuweni.units.bigints.UInt256;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

public class P256EdgeCaseTest {

    // P-256 curve order (n) as defined in FIPS 186-4
    private static final BigInteger CURVE_ORDER = new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);
    
    // Valid test vectors from existing tests
    private final Bytes validDataHash = Bytes.fromHexString("c35e2f092553c55772926bdbe87c9796827d17024dbb9233a545366e2e5987dd344deb72df987144b8c6c43bc41b654b94cc856e16b96d7a821c8ec039b503e3d86728c494a967d83011a0e090b5d54cd47f4e366c0912bc808fbb2ea96efac88fb3ebec9342738e225f7c7c2b011ce375b56621a20642b4d36e060db4524af1");
    private final Bytes validPublicKey = Bytes.fromHexString("e266ddfdc12668db30d4ca3e8f7749432c416044f2d2b8c10bf3d4012aeffa8abfa86404a2e9ffe67d47c587ef7a97a7f456b863b4d02cfc6928973ab5b1cb39");
    private final Bytes validSignatureR = Bytes.fromHexString("976d3a4e9d23326dc0baa9fa560b7c4e53f42864f508483a6473b6a11079b2db");
    private final Bytes validSignatureS = Bytes.fromHexString("1b766e9ceb71ba6c01dcd46e0af462cd4cfa652ae5017d4555b8eeefe36e1932");
    
    private byte[] testDataHash;

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        Assume.assumeTrue("P256Verify must be enabled", BoringSSLPrecompiles.ENABLED);
        
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        testDataHash = digest.digest(validDataHash.toArrayUnsafe());
    }

    // 1. Signature Scalar Range Violations
    
    @Test
    public void testSignatureRIsZero() {
        // ECDSA requires r != 0 - this should fail
        byte[] input = createInput(testDataHash, new byte[32], validSignatureS.toArrayUnsafe(), validPublicKey.toArrayUnsafe());
        
        var result = BoringSSLPrecompiles.p256Verify(input, input.length);

        assertThat(result.status).isEqualTo(1);
        assertThat(result.error).isEqualTo("signature verification failed");
    }

    @Test
    public void testSignatureSIsZero() {
        // ECDSA requires s != 0 - this should fail
        byte[] input = createInput(testDataHash, validSignatureR.toArrayUnsafe(), new byte[32], validPublicKey.toArrayUnsafe());
        
        var result = BoringSSLPrecompiles.p256Verify(input, input.length);

        assertThat(result.status).isEqualTo(1);
        assertThat(result.error).isEqualTo("signature verification failed");
    }

    @Test
    public void testSignatureREqualsOrder() {
        // r >= curve_order should be invalid
        byte[] rEqualsOrder = toBytes32(CURVE_ORDER);
        byte[] input = createInput(testDataHash, rEqualsOrder, validSignatureS.toArrayUnsafe(), validPublicKey.toArrayUnsafe());
        
        var result = BoringSSLPrecompiles.p256Verify(input, input.length);

        assertThat(result.status).isEqualTo(1);
        assertThat(result.error).isEqualTo("signature verification failed");
    }

    @Test
    public void testSignatureSEqualsOrder() {
        // s >= curve_order should be invalid
        byte[] sEqualsOrder = toBytes32(CURVE_ORDER);
        byte[] input = createInput(testDataHash, validSignatureR.toArrayUnsafe(), sEqualsOrder, validPublicKey.toArrayUnsafe());
        
        var result = BoringSSLPrecompiles.p256Verify(input, input.length);

        assertThat(result.status).isEqualTo(1);
        assertThat(result.error).isEqualTo("signature verification failed");
    }

    @Test
    public void testSignatureRGreaterThanOrder() {
        // r > curve_order should be invalid
        byte[] rGreaterThanOrder = new byte[32];
        Arrays.fill(rGreaterThanOrder, (byte) 0xFF); // Maximum 256-bit value
        byte[] input = createInput(testDataHash, rGreaterThanOrder, validSignatureS.toArrayUnsafe(), validPublicKey.toArrayUnsafe());
        
        var result = BoringSSLPrecompiles.p256Verify(input, input.length);

        assertThat(result.status).isEqualTo(1);
        assertThat(result.error).isEqualTo("signature verification failed");
    }

    @Test
    public void testSignatureSGreaterThanOrder() {
        // s > curve_order should be invalid
        byte[] sGreaterThanOrder = new byte[32];
        Arrays.fill(sGreaterThanOrder, (byte) 0xFF); // Maximum 256-bit value
        byte[] input = createInput(testDataHash, validSignatureR.toArrayUnsafe(), sGreaterThanOrder, validPublicKey.toArrayUnsafe());
        
        var result = BoringSSLPrecompiles.p256Verify(input, input.length);

        assertThat(result.status).isEqualTo(1);
        assertThat(result.error).isEqualTo("signature verification failed");
    }

    // 2. Public Key Edge Cases

    @Test
    public void testPublicKeyPointAtInfinity() {
        // Point at infinity (all zeros) should be invalid
        byte[] pointAtInfinity = new byte[64];
        byte[] input = createInput(testDataHash, validSignatureR.toArrayUnsafe(), validSignatureS.toArrayUnsafe(), pointAtInfinity);
        
        var result = BoringSSLPrecompiles.p256Verify(input, input.length);

        assertThat(result.status).isEqualTo(1);
        assertThat(result.error).isEqualTo("failed to parse public key point");
    }

    @Test
    public void testPublicKeyNotOnCurve() {
        // Create a point that's definitely not on the P-256 curve
        byte[] invalidPoint = new byte[64];
        Arrays.fill(invalidPoint, (byte) 0x42); // All bytes set to 0x42
        byte[] input = createInput(testDataHash, validSignatureR.toArrayUnsafe(), validSignatureS.toArrayUnsafe(), invalidPoint);
        
        var result = BoringSSLPrecompiles.p256Verify(input, input.length);

        assertThat(result.status).isEqualTo(1);
        assertThat(result.error).isEqualTo("failed to parse public key point");
    }

    // 3. Hash Edge Cases

    @Test
    public void testAllZeroHash() {
        // All zero hash (z = 0) - corner case
        byte[] allZeroHash = new byte[32];
        byte[] input = createInput(allZeroHash, validSignatureR.toArrayUnsafe(), validSignatureS.toArrayUnsafe(), validPublicKey.toArrayUnsafe());
        
        var result = BoringSSLPrecompiles.p256Verify(input, input.length);

        assertThat(result.status).isEqualTo(1);
        assertThat(result.error).isEqualTo("signature verification failed");
    }

    @Test
    public void testAllOnesHash() {
        // All ones hash (z = 0xFFFF...FFFF)
        byte[] allOnesHash = new byte[32];
        Arrays.fill(allOnesHash, (byte) 0xFF);
        byte[] input = createInput(allOnesHash, validSignatureR.toArrayUnsafe(), validSignatureS.toArrayUnsafe(), validPublicKey.toArrayUnsafe());
        
        var result = BoringSSLPrecompiles.p256Verify(input, input.length);

        assertThat(result.status).isEqualTo(1);
        assertThat(result.error).isEqualTo("signature verification failed");
    }

    @Test
    public void testHashEqualsOrder() {
        // Message hash exactly equal to curve order
        byte[] hashEqualsOrder = toBytes32(CURVE_ORDER);
        byte[] input = createInput(hashEqualsOrder, validSignatureR.toArrayUnsafe(), validSignatureS.toArrayUnsafe(), validPublicKey.toArrayUnsafe());
        
        var result = BoringSSLPrecompiles.p256Verify(input, input.length);

        assertThat(result.status).isEqualTo(1);
        assertThat(result.error).isEqualTo("signature verification failed");
    }

    // 4. Input Size Edge Cases

    @Test
    public void testIncorrectInputSize() {
        // Test with wrong input size (not 160 bytes)
        byte[] shortInput = new byte[128]; // Too short
        Arrays.fill(shortInput, (byte) 0x01);
        
        var result = BoringSSLPrecompiles.p256Verify(shortInput, shortInput.length);

        assertThat(result.status).isEqualTo(2);
        assertThat(result.error).isEqualTo("incorrect input size");
    }

    // 5. Malleability Conditions

    @Test
    public void testMalleatedSignatureHighS() {
        // Test signature with s > n/2 (valid but not canonical)
        // This should still verify according to EIP-7951 which doesn't require canonical signatures
        UInt256 order = UInt256.fromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        UInt256 malleatedS = order.subtract(UInt256.fromBytes(validSignatureS));
        byte[] input = createInput(testDataHash, validSignatureR.toArrayUnsafe(), malleatedS.toArrayUnsafe(), validPublicKey.toArrayUnsafe());
        
        var result = BoringSSLPrecompiles.p256Verify(input, input.length);

        assertThat(result.status).isEqualTo(0); // Should pass per EIP-7951
    }

    @Test
    public void testSignatureRPrimeMismatch() {
        // Test where computed R'.x mod n != r
        // Use a valid R but with wrong signature components
        byte[] wrongR = validSignatureR.toArrayUnsafe().clone();
        wrongR[31] ^= 0x01; // Flip one bit to make it wrong but still in valid range
        byte[] input = createInput(testDataHash, wrongR, validSignatureS.toArrayUnsafe(), validPublicKey.toArrayUnsafe());
        
        var result = BoringSSLPrecompiles.p256Verify(input, input.length);

        assertThat(result.status).isEqualTo(1);
        assertThat(result.error).isEqualTo("signature verification failed");
    }

    // 6. Positive Test Cases

    @Test
    public void testKnownValidSignature() {
        // Test with known valid signature to ensure positive cases work
        byte[] input = createInput(testDataHash, validSignatureR.toArrayUnsafe(), validSignatureS.toArrayUnsafe(), validPublicKey.toArrayUnsafe());
        
        var result = BoringSSLPrecompiles.p256Verify(input, input.length);

        assertThat(result.status).isEqualTo(0);
        assertThat(result.error).isEmpty();
    }

    // Helper method to convert BigInteger to 32-byte array
    private byte[] toBytes32(BigInteger value) {
        byte[] bytes = value.toByteArray();
        byte[] result = new byte[32];
        
        if (bytes.length <= 32) {
            System.arraycopy(bytes, 0, result, 32 - bytes.length, bytes.length);
        } else {
            System.arraycopy(bytes, bytes.length - 32, result, 0, 32);
        }
        
        return result;
    }

    // Helper method to create 160-byte input array: hash(32) + r(32) + s(32) + pubkey(64)
    private byte[] createInput(byte[] hash, byte[] r, byte[] s, byte[] pubkey) {
        if (hash.length != 32 || r.length != 32 || s.length != 32 || pubkey.length != 64) {
            throw new IllegalArgumentException("Invalid component lengths for input creation");
        }
        
        byte[] input = new byte[160];
        System.arraycopy(hash, 0, input, 0, 32);
        System.arraycopy(r, 0, input, 32, 32);
        System.arraycopy(s, 0, input, 64, 32);
        System.arraycopy(pubkey, 0, input, 96, 64);
        return input;
    }
}
