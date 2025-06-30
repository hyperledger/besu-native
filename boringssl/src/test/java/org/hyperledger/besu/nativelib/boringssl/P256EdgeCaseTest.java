/*
 * Copyright Hyperledger Besu contributors.
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
 */

package org.hyperledger.besu.nativelib.boringssl;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt256;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
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
        Assume.assumeTrue("P256Verify must be enabled", LibP256Verify.ENABLED);
        
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        testDataHash = digest.digest(validDataHash.toArrayUnsafe());
    }

    // 1. Signature Scalar Range Violations
    
    @Test
    public void testSignatureRIsZero() {
        // ECDSA requires r != 0 - this should fail
        byte[] zeroR = new byte[32]; // All zeros
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            zeroR,
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );

        // This will fail signature verification, but not parameter error
        assertThat(result.status).isEqualTo(1);
        assertThat(result.message).isEqualTo("signature verification failed");
    }

    @Test
    public void testSignatureSIsZero() {
        // ECDSA requires s != 0 - this should fail
        byte[] zeroS = new byte[32]; // All zeros
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            validSignatureR.toArrayUnsafe(),
            zeroS,
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );

        // This will fail signature verification, but not parameter error
        assertThat(result.status).isEqualTo(1); // Either valid or verification failed, but not parameter error
        assertThat(result.message).isEqualTo("signature verification failed");
    }

    @Test
    public void testSignatureREqualsOrder() {
        // r >= curve_order should be invalid
        byte[] rEqualsOrder = CURVE_ORDER.toByteArray();
        if (rEqualsOrder.length > 32) {
            // Remove leading zero if present
            rEqualsOrder = Arrays.copyOfRange(rEqualsOrder, rEqualsOrder.length - 32, rEqualsOrder.length);
        }
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            rEqualsOrder,
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );

        // This will fail signature verification, but not parameter error
        assertThat(result.status).isEqualTo(1);
        assertThat(result.message).isEqualTo("signature verification failed");
    }

    @Test
    public void testSignatureSEqualsOrder() {
        // s >= curve_order should be invalid
        byte[] sEqualsOrder = CURVE_ORDER.toByteArray();
        if (sEqualsOrder.length > 32) {
            // Remove leading zero if present
            sEqualsOrder = Arrays.copyOfRange(sEqualsOrder, sEqualsOrder.length - 32, sEqualsOrder.length);
        }
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            validSignatureR.toArrayUnsafe(),
            sEqualsOrder,
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );

        // This will fail signature verification, but not parameter error
        assertThat(result.status).isEqualTo(1);
        assertThat(result.message).isEqualTo("signature verification failed");
    }

    @Test
    public void testSignatureRMaxValid() {
        // r = curve_order - 1 should be the maximum valid r value
        BigInteger maxValidR = CURVE_ORDER.subtract(BigInteger.ONE);
        byte[] maxRBytes = toBytes32(maxValidR);
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            maxRBytes,
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );
        
        // This will fail verification due to mismatched signature, but should not fail input validation
        // The important thing is it doesn't crash or return invalid parameter error
        assertThat(result.status).isEqualTo(1); // Either valid or verification failed, but not parameter error
        assertThat(result.message).isEqualTo("signature verification failed");
    }

    @Test
    public void testSignatureSMaxValid() {
        // s = curve_order - 1 should be the maximum valid s value
        BigInteger maxValidS = CURVE_ORDER.subtract(BigInteger.ONE);
        byte[] maxSBytes = toBytes32(maxValidS);
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            validSignatureR.toArrayUnsafe(),
            maxSBytes,
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );
        
        // This will fail verification due to mismatched signature, but should not fail input validation
        assertThat(result.status).isEqualTo(1); // Either valid or verification failed, but not parameter error
        assertThat(result.message).isEqualTo("signature verification failed");
    }

    @Test
    public void testSignatureRGreaterThanOrder() {
        // r > curve_order should be invalid
        byte[] rGreaterThanOrder = new byte[32];
        Arrays.fill(rGreaterThanOrder, (byte) 0xFF); // Maximum 256-bit value
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            rGreaterThanOrder,
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );

        assertThat(result.message).isEqualTo("signature verification failed");
        assertThat(result.status).isNotEqualTo(0);
    }

    @Test
    public void testSignatureSGreaterThanOrder() {
        // s > curve_order should be invalid
        byte[] sGreaterThanOrder = new byte[32];
        Arrays.fill(sGreaterThanOrder, (byte) 0xFF); // Maximum 256-bit value
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            validSignatureR.toArrayUnsafe(),
            sGreaterThanOrder,
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );

        assertThat(result.status).isEqualTo(1); // Either valid or verification failed, but not parameter error
        assertThat(result.message).isEqualTo("signature verification failed");
    }

    // 2. Public Key Edge Cases

    @Test
    public void testPublicKeyPointAtInfinity() {
        // Point at infinity (all zeros) should be invalid
        byte[] pointAtInfinity = new byte[64];
        // Already all zeros
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            validSignatureR.toArrayUnsafe(),
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(pointAtInfinity)
        );

        assertThat(result.status).isEqualTo(1);
        assertThat(result.message).isEqualTo("failed to parse public key point");
    }

    @Test
    public void testPublicKeyNotOnCurve() {
        // P-256 has cofactor=1, so all valid public keys are in the correct subgroup.
        // This test constructs a point with valid field coordinates but that does NOT
        // lie on the curve (violates y^2 != x^3 + ax + b) — should be rejected.

        BigInteger fieldPrime = new BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16);
        BigInteger maxX = fieldPrime.subtract(BigInteger.ONE);

        byte[] invalidPoint = new byte[64];
        byte[] xBytes = toBytes32(maxX);
        System.arraycopy(xBytes, 0, invalidPoint, 0, 32);

        // Arbitrary y value that likely doesn't satisfy curve equation
        Arrays.fill(invalidPoint, 32, 64, (byte) 0x01);

        var result = LibP256Verify.p256Verify(
            testDataHash,
            validSignatureR.toArrayUnsafe(),
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(invalidPoint)
        );

        assertThat(result.status).isEqualTo(1);
        assertThat(result.message).isEqualTo("failed to parse public key point");
    }

    @Test
    public void testMalformedPublicKeyWrongLength() {
        // Test with wrong public key length (should be 64 bytes without prefix)
        byte[] wrongLengthKey = new byte[63]; // One byte short
        Arrays.fill(wrongLengthKey, (byte) 0x01);
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            validSignatureR.toArrayUnsafe(),
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(wrongLengthKey)
        );
        
        assertThat(result.status).isEqualTo(1);
        assertThat(result.message).isEqualTo("failed to parse public key point");
    }

    @Test
    public void testPublicKeyWithInvalidPrefix() {
        // Test with wrong prefix (should be 0x04 for uncompressed)
        byte[] keyWithWrongPrefix = new byte[65];
        keyWithWrongPrefix[0] = 0x02; // Wrong prefix
        System.arraycopy(validPublicKey.toArrayUnsafe(), 0, keyWithWrongPrefix, 1, 64);
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            validSignatureR.toArrayUnsafe(),
            validSignatureS.toArrayUnsafe(),
            keyWithWrongPrefix // Don't use prefixPublicKey since we're testing the prefix
        );
        
        assertThat(result.status).isEqualTo(1);
        assertThat(result.message).isEqualTo("public key must start with 0x04");
    }

    // 3. Message Hash Edge Cases

    @Test
    public void testAllZeroHash() {
        // All zero hash (z = 0) - corner case
        byte[] allZeroHash = new byte[32];
        // Already all zeros
        
        var result = LibP256Verify.p256Verify(
            allZeroHash,
            validSignatureR.toArrayUnsafe(),
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );
        
        // This should not fail due to hash being zero, but signature verification will likely fail
        assertThat(result.status).isEqualTo(1); // Either valid or verification failed, but not parameter error
        assertThat(result.message).isEqualTo("signature verification failed");
    }

    @Test
    public void testAllOnesHash() {
        // All ones hash (z = 0xFFFF...FFFF)
        byte[] allOnesHash = new byte[32];
        Arrays.fill(allOnesHash, (byte) 0xFF);
        
        var result = LibP256Verify.p256Verify(
            allOnesHash,
            validSignatureR.toArrayUnsafe(),
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );
        
        // This should not fail due to hash content, but signature verification will likely fail
        assertThat(result.status).isEqualTo(1); // Either valid or verification failed, but not parameter error
        assertThat(result.message).isEqualTo("signature verification failed");
    }

    @Test
    public void testHashEqualsOrder() {
        // Message hash exactly equal to curve order
        byte[] hashEqualsOrder = CURVE_ORDER.toByteArray();
        if (hashEqualsOrder.length > 32) {
            hashEqualsOrder = Arrays.copyOfRange(hashEqualsOrder, hashEqualsOrder.length - 32, hashEqualsOrder.length);
        }
        
        var result = LibP256Verify.p256Verify(
            hashEqualsOrder,
            validSignatureR.toArrayUnsafe(),
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );
        
        // This should not fail due to hash content, but signature verification will likely fail
        assertThat(result.status).isEqualTo(1); // Either valid or verification failed, but not parameter error
        assertThat(result.message).isEqualTo("signature verification failed");

    }

    @Test
    public void testWrongHashLength() {
        // Test with wrong hash length (too short)
        byte[] shortHash = new byte[16]; // Half the expected length
        Arrays.fill(shortHash, (byte) 0x01);
        
        var result = LibP256Verify.p256Verify(
            shortHash,
            validSignatureR.toArrayUnsafe(),
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );
        
        assertThat(result.status).isEqualTo(2);
        assertThat(result.message).isEqualTo("invalid hash length");

    }

    @Test
    public void testOversizedHash() {
        // Test with oversized hash (too long)
        byte[] longHash = new byte[64]; // Double the expected length
        Arrays.fill(longHash, (byte) 0x01);
        
        var result = LibP256Verify.p256Verify(
            longHash,
            validSignatureR.toArrayUnsafe(),
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );

        assertThat(result.status).isEqualTo(2);
        assertThat(result.message).isEqualTo("invalid hash length");

    }

    // 4. Implementation-Focused Checks

    @Test
    public void testNullDataHash() {
        // Test null data hash
        var result = LibP256Verify.p256Verify(
            null,
            validSignatureR.toArrayUnsafe(),
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );
        
        assertThat(result.status).isEqualTo(2);
        assertThat(result.message).isEqualTo("null message hash");
    }

    @Test
    public void testNullSignatureR() {
        // Test null signature R
        var result = LibP256Verify.p256Verify(
            testDataHash,
            null,
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );
        
        assertThat(result.status).isEqualTo(2);
        assertThat(result.message).isEqualTo("null input");
    }

    @Test
    public void testNullSignatureS() {
        // Test null signature S
        var result = LibP256Verify.p256Verify(
            testDataHash,
            validSignatureR.toArrayUnsafe(),
            null,
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );
        
        assertThat(result.status).isEqualTo(2);
        assertThat(result.message).isEqualTo("null input");
    }

    @Test
    public void testNullPublicKey() {
        // Test null public key
        var result = LibP256Verify.p256Verify(
            testDataHash,
            validSignatureR.toArrayUnsafe(),
            validSignatureS.toArrayUnsafe(),
            null
        );
        
        assertThat(result.status).isEqualTo(2);
        assertThat(result.message).isEqualTo("null input");
    }

    @Test
    public void testEmptyArrays() {
        // Test with empty arrays
        byte[] empty = new byte[0];
        
        var result = LibP256Verify.p256Verify(
            empty,
            empty,
            empty,
            empty
        );
        
        assertThat(result.status).isEqualTo(2);
    }

    @Test
    public void testSignatureComponentsWrongLength() {
        // Test signature components with wrong length
        byte[] shortR = new byte[16];
        byte[] shortS = new byte[16];
        Arrays.fill(shortR, (byte) 0x01);
        Arrays.fill(shortS, (byte) 0x02);
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            shortR,
            shortS,
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );
        
        assertThat(result.status).isEqualTo(1);
        assertThat(result.message).isEqualTo("signature verification failed");
    }

    // 5. Replay/Malleability Conditions

    @Test
    public void testMalleatedSignatureHighS() {
        // Test signature with s > n/2 (valid but not canonical)
        // This should still verify according to EIP-7951 which doesn't require canonical signatures
        UInt256 order = UInt256.fromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        UInt256 highS = order.subtract(UInt256.valueOf(1)); // n - 1, which is > n/2
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            validSignatureR.toArrayUnsafe(),
            highS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );
        
        // Should not fail due to high S value, though verification may fail for other reasons
        assertThat(result.status).isIn(0, 1);
    }

    @Test
    public void testSignatureRPrimeMismatch() {
        // Test where computed R'.x mod n != r
        // Use a valid R but with wrong signature components
        byte[] wrongR = validSignatureR.toArrayUnsafe().clone();
        wrongR[31] ^= 0x01; // Flip one bit to make it wrong but still in valid range
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            wrongR,
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );

        assertThat(result.status).isEqualTo(1); // Either valid or verification failed, but not parameter error
        assertThat(result.message).isEqualTo("signature verification failed");
    }

    // 6. Positive Test Cases with Known Vectors

    @Test
    public void testKnownValidSignature() {
        // Test with known valid signature to ensure positive cases work
        var result = LibP256Verify.p256Verify(
            testDataHash,
            validSignatureR.toArrayUnsafe(),
            validSignatureS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );
        
        assertThat(result.status).isEqualTo(0);
        assertThat(result.message).isEmpty();
    }

    @Test
    public void testMalleatedButValidSignature() {
        // Test malleated signature (s' = n - s) which should still be valid per EIP-7951
        UInt256 order = UInt256.fromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        UInt256 originalS = UInt256.fromBytes(validSignatureS);
        UInt256 malleatedS = order.subtract(originalS);
        
        var result = LibP256Verify.p256Verify(
            testDataHash,
            validSignatureR.toArrayUnsafe(),
            malleatedS.toArrayUnsafe(),
            LibP256Verify.prefixPublicKey(validPublicKey.toArrayUnsafe())
        );
        
        assertThat(result.status).isEqualTo(0);
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
}
