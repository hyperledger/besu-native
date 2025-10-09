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
package org.hyperledger.besu.nativelib.gnark;

import java.nio.charset.StandardCharsets;

/**
 * Test harness for LibGnarkEIP2537Graal to verify G2 point validation operations.
 * Exercises the GraalVM native wrapper with various test cases.
 */
public class GraalG2PointTest {

    // Valid G2 point - zero point (point at infinity) - 256 bytes (512 hex chars)
    private static final String VALID_G2_POINT =
        "00000000000000000000000000000000124aca13d9ead2e5194eb097360743fc996551a5f339d644ded3571c5588a1fedf3f26ecdca73845241e47337e8ad990" +
        "000000000000000000000000000000000299bfd77515b688335e58acb31f7e0e6416840989cb08775287f90f7e6c921438b7b476cfa387742fcdc43bcecfe45f" +
        "00000000000000000000000000000000032e78350f525d673e75a3430048a7931d21264ac1b2c8dc58aee07e77790dfc9afb530b004145f0040c48bce128135e" +
        "0000000000000000000000000000000015963bcbd8fa50808bdce4f8de40eb9706c1a41ada22f0e469ecceb3e0b0fa3404ccdcc66a286b5a9e221c4a088a9145";

    // Invalid G2 point (not on curve)
    private static final String INVALID_G2_POINT_NOT_ON_CURVE =
        "000000000000000000000000000000000b2c619263417e8f6cffa2e53261cb8cf5fbbabb9e6f4188aeaabe50d434a0489b6cccd2b65b4d1393a26911021baffa" +
        "00000000000000000000000000000000007bcd4156af7ebe5e2f6ac63db859c9f42d5f11682792a0de2ec1db76648c0c98fdd8a82cf640bdcd309901afd4f570" +
        "00000000000000000000000000000000153a9002d117a518b2c1786f9e8b95b00e936f3f15302a27a16d7f2f8fc48ca834c0cf4fce456e96d72f01f252f4d084" +
        "000000000000000000000000000000001091fc53100190db07ec2057727859e65da996f6792ac5602cb9dfbc3ed4a5a67d6b82bd82112075ef8afc4155db2621";

    // G2 point that's on curve but not in subgroup
    private static final String G2_POINT_NOT_IN_SUBGROUP =
        "000000000000000000000000000000000380f5c0d9ae49e3904c5ae7ad83043158d68fa721b06b561e714b71a2c48c2307b5258892f999a882bed3549a286b7f" +
        "0000000000000000000000000000000004886f7f17a8e9918b4bfa8ebe450b0216ed5e1fa103dfc671332dc38b04ed3105526fb0dda7e032b6fb67debf9f0bc5" +
        "0000000000000000000000000000000018146b7ed1ecf2a4f2d1f75bb6e9ddbb9796bb03576686346995566cf3b3831ec5462e61028355504fc90f877408ac17" +
        "0000000000000000000000000000000003da9de8dcd94d7793b19e45a5521b1bc42f1a6d693139d03bb26402678ee6a635a4d50eaddfd326e446ed0330fa67fb";

    // Invalid padding (non-zero leading bytes)
    private static final String INVALID_G2_PADDING =
        "01000000000000000000000000000000124aca13d9ead2e5194eb097360743fc996551a5f339d644ded3571c5588a1fedf3f26ecdca73845241e47337e8ad990" +
        "000000000000000000000000000000000299bfd77515b688335e58acb31f7e0e6416840989cb08775287f90f7e6c921438b7b476cfa387742fcdc43bcecfe45f" +
        "00000000000000000000000000000000032e78350f525d673e75a3430048a7931d21264ac1b2c8dc58aee07e77790dfc9afb530b004145f0040c48bce128135e" +
        "0000000000000000000000000000000015963bcbd8fa50808bdce4f8de40eb9706c1a41ada22f0e469ecceb3e0b0fa3404ccdcc66a286b5a9e221c4a088a9145";

    // Invalid length input
    private static final String INVALID_LENGTH_INPUT = "0001020304";

    public static void main(String[] args) {
        System.out.println("========================================");
        System.out.println("LibGnarkEIP2537Graal G2 Point Test");
        System.out.println("========================================\n");

        // Test 1: Valid G2 point - should be on curve
        testG2IsOnCurve_ValidPoint();

        // Test 2: Invalid G2 point - not on curve
        testG2IsOnCurve_InvalidPoint();

        // Test 3: Invalid padding
        testG2IsOnCurve_InvalidPadding();

        // Test 4: Invalid length
        testG2IsOnCurve_InvalidLength();

        // Test 5: Valid point in subgroup
        testG2IsInSubGroup_ValidPoint();

        // Test 6: Point not in subgroup
        testG2IsInSubGroup_NotInSubGroup();

        // Test 7: Point not on curve (subgroup test)
        testG2IsInSubGroup_NotOnCurve();

        // Test 8: Zero point (point at infinity)
        testG2IsOnCurve_ZeroPoint();

        System.out.println("\n========================================");
        System.out.println("All tests completed");
        System.out.println("========================================");
    }

    private static void testG2IsOnCurve_ValidPoint() {
        System.out.println("TEST 1: G2 IsOnCurve - Valid Point");
        System.out.println("-----------------------------------");

        final byte[] input = hexStringToBytes(VALID_G2_POINT);
        final byte[] error = new byte[LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];

        System.out.println("Input (hex): " + VALID_G2_POINT);
        System.out.println("Input length: " + input.length + " bytes");

        boolean result = LibGnarkEIP2537Graal.eip2537G2IsOnCurve(
            input, error, input.length, LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);

        System.out.println("Result: " + result);
        System.out.println("Expected: true");
        System.out.println("Status: " + (result ? "PASS" : "FAIL"));
        printError(error);
        System.out.println();
    }

    private static void testG2IsOnCurve_InvalidPoint() {
        System.out.println("TEST 2: G2 IsOnCurve - Invalid Point (Not On Curve)");
        System.out.println("----------------------------------------------------");

        final byte[] input = hexStringToBytes(INVALID_G2_POINT_NOT_ON_CURVE);
        final byte[] error = new byte[LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];

        System.out.println("Input (hex): " + INVALID_G2_POINT_NOT_ON_CURVE);
        System.out.println("Input length: " + input.length + " bytes");

        boolean result = LibGnarkEIP2537Graal.eip2537G2IsOnCurve(
            input, error, input.length, LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);

        System.out.println("Result: " + result);
        System.out.println("Expected: false");
        System.out.println("Status: " + (!result ? "PASS" : "FAIL"));
        printError(error);
        System.out.println();
    }

    private static void testG2IsOnCurve_InvalidPadding() {
        System.out.println("TEST 3: G2 IsOnCurve - Invalid Padding");
        System.out.println("---------------------------------------");

        final byte[] input = hexStringToBytes(INVALID_G2_PADDING);
        final byte[] error = new byte[LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];

        System.out.println("Input (hex): " + INVALID_G2_PADDING);
        System.out.println("Input length: " + input.length + " bytes");

        boolean result = LibGnarkEIP2537Graal.eip2537G2IsOnCurve(
            input, error, input.length, LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);

        System.out.println("Result: " + result);
        System.out.println("Expected: false");
        System.out.println("Status: " + (!result ? "PASS" : "FAIL"));
        printError(error);
        System.out.println();
    }

    private static void testG2IsOnCurve_InvalidLength() {
        System.out.println("TEST 4: G2 IsOnCurve - Invalid Length");
        System.out.println("--------------------------------------");

        final byte[] input = hexStringToBytes(INVALID_LENGTH_INPUT);
        final byte[] error = new byte[LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];

        System.out.println("Input (hex): " + INVALID_LENGTH_INPUT);
        System.out.println("Input length: " + input.length + " bytes");

        boolean result = LibGnarkEIP2537Graal.eip2537G2IsOnCurve(
            input, error, input.length, LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);

        System.out.println("Result: " + result);
        System.out.println("Expected: false");
        System.out.println("Status: " + (!result ? "PASS" : "FAIL"));
        printError(error);
        System.out.println();
    }

    private static void testG2IsInSubGroup_ValidPoint() {
        System.out.println("TEST 5: G2 IsInSubGroup - Valid Point");
        System.out.println("--------------------------------------");

        final byte[] input = hexStringToBytes(VALID_G2_POINT);
        final byte[] error = new byte[LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];

        System.out.println("Input (hex): " + VALID_G2_POINT);
        System.out.println("Input length: " + input.length + " bytes");

        boolean result = LibGnarkEIP2537Graal.eip2537G2IsInSubGroup(
            input, error, input.length, LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);

        System.out.println("Result: " + result);
        System.out.println("Expected: true");
        System.out.println("Status: " + (result ? "PASS" : "FAIL"));
        printError(error);
        System.out.println();
    }

    private static void testG2IsInSubGroup_NotInSubGroup() {
        System.out.println("TEST 6: G2 IsInSubGroup - Point Not In Subgroup");
        System.out.println("------------------------------------------------");

        final byte[] input = hexStringToBytes(G2_POINT_NOT_IN_SUBGROUP);
        final byte[] error = new byte[LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];

        System.out.println("Input (hex): " + G2_POINT_NOT_IN_SUBGROUP);
        System.out.println("Input length: " + input.length + " bytes");

        boolean result = LibGnarkEIP2537Graal.eip2537G2IsInSubGroup(
            input, error, input.length, LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);

        System.out.println("Result: " + result);
        System.out.println("Expected: false");
        System.out.println("Status: " + (!result ? "PASS" : "FAIL"));
        printError(error);
        System.out.println();
    }

    private static void testG2IsInSubGroup_NotOnCurve() {
        System.out.println("TEST 7: G2 IsInSubGroup - Point Not On Curve");
        System.out.println("---------------------------------------------");

        final byte[] input = hexStringToBytes(INVALID_G2_POINT_NOT_ON_CURVE);
        final byte[] error = new byte[LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];

        System.out.println("Input (hex): " + INVALID_G2_POINT_NOT_ON_CURVE);
        System.out.println("Input length: " + input.length + " bytes");

        boolean result = LibGnarkEIP2537Graal.eip2537G2IsInSubGroup(
            input, error, input.length, LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);

        System.out.println("Result: " + result);
        System.out.println("Expected: false");
        System.out.println("Status: " + (!result ? "PASS" : "FAIL"));
        printError(error);
        System.out.println();
    }

    private static void testG2IsOnCurve_ZeroPoint() {
        System.out.println("TEST 8: G2 IsOnCurve - Zero Point (Point at Infinity)");
        System.out.println("-----------------------------------------------------");

        final byte[] input = new byte[256]; // All zeros
        final byte[] error = new byte[LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];

        System.out.println("Input: <256 zero bytes>");
        System.out.println("Input length: " + input.length + " bytes");

        boolean result = LibGnarkEIP2537Graal.eip2537G2IsOnCurve(
            input, error, input.length, LibGnarkEIP2537Graal.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);

        System.out.println("Result: " + result);
        System.out.println("Expected: true");
        System.out.println("Status: " + (result ? "PASS" : "FAIL"));
        printError(error);
        System.out.println();
    }

    private static void printError(byte[] error) {
        int errorLen = LibGnarkUtils.findFirstTrailingZeroIndex(error);
        if (errorLen > 0) {
            String errorMsg = new String(error, 0, errorLen, StandardCharsets.UTF_8);
            System.out.println("Error message: " + errorMsg);
        } else {
            System.out.println("Error message: <none>");
        }
    }

    /**
     * Convert hex string to byte array
     */
    private static byte[] hexStringToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                                 + Character.digit(hex.charAt(i+1), 16));
        }
        return data;
    }
}
