/*
 * Copyright Besu Contributors
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

import org.apache.tuweni.bytes.Bytes;
import org.junit.Ignore;
import org.junit.Test;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

public class BLS12PointDecodingTests {

  // Valid G1 point from existing test data - 128 bytes with proper padding
  private static final String VALID_G1_POINT = 
      "0000000000000000000000000000000012196c5a43d69224d8713389285f26b98f86ee910ab3dd668e413738282003cc5b7357af9a7af54bb713d62255e80f56" +
      "0000000000000000000000000000000006ba8102bfbeea4416b710c73e8cce3032c31c6269c44906f8ac4f7874ce99fb17559992486528963884ce429a992fee";

  // Valid G2 point - zero point (point at infinity) - 256 bytes (512 hex chars)
  private static final String VALID_G2_POINT = 
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

  // Invalid G1 point (not on curve) - modified valid point by changing last byte
  private static final String INVALID_G1_POINT_NOT_ON_CURVE =
      "0000000000000000000000000000000012196c5a43d69224d8713389285f26b98f86ee910ab3dd668e413738282003cc5b7357af9a7af54bb713d62255e80f56" +
      "0000000000000000000000000000000006ba8102bfbeea4416b710c73e8cce3032c31c6269c44906f8ac4f7874ce99fb17559992486528963884ce429a992fef"; // Changed last byte

  // Invalid G2 point (not on curve) - modified zero point by changing last byte  
  private static final String INVALID_G2_POINT_NOT_ON_CURVE =
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001"; // Changed last byte

  // G1 point that's on curve but not in subgroup - use a simple test point (256 hex chars)
  private static final String G1_POINT_NOT_IN_SUBGROUP =
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001" +
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002";

  // G2 point that's on curve but not in subgroup - use a simple test point (512 hex chars)  
  private static final String G2_POINT_NOT_IN_SUBGROUP =
      "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000200000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000";

  // Invalid padding (non-zero leading bytes)
  private static final String INVALID_G1_PADDING =
      "0100000000000000000000000000000012196c5a43d69224d8713389285f26b98f86ee910ab3dd668e413738282003cc5b7357af9a7af54bb713d62255e80f56" +
      "0000000000000000000000000000000006ba8102bfbeea4416b710c73e8cce3032c31c6269c44906f8ac4f7874ce99fb17559992486528963884ce429a992fee";

  // Invalid length input
  private static final String INVALID_LENGTH_INPUT = "0001020304";

  @Test
  public void testG1IsOnCurve_ValidPoint() {
    final byte[] input = Bytes.fromHexString(VALID_G1_POINT).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G1IsOnCurve(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isTrue();
  }

  @Test
  public void testG1IsOnCurve_InvalidPoint() {
    final byte[] input = Bytes.fromHexString(INVALID_G1_POINT_NOT_ON_CURVE).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G1IsOnCurve(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isFalse();
    // Verify error message contains expected text
    String errorMsg = new String(error, 0, LibGnarkUtils.findFirstTrailingZeroIndex(error), UTF_8);
    assertThat(errorMsg).contains("invalid point: point is not on curve");
  }

  @Test  
  public void testG1IsOnCurve_InvalidPadding() {
    final byte[] input = Bytes.fromHexString(INVALID_G1_PADDING).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G1IsOnCurve(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isFalse();
    String errorMsg = new String(error, 0, LibGnarkUtils.findFirstTrailingZeroIndex(error), UTF_8);
    assertThat(errorMsg).contains("invalid point: point is not left padded with zero");
  }

  @Test
  public void testG1IsOnCurve_InvalidLength() {
    final byte[] input = Bytes.fromHexString(INVALID_LENGTH_INPUT).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G1IsOnCurve(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isFalse();
    String errorMsg = new String(error, 0, LibGnarkUtils.findFirstTrailingZeroIndex(error), UTF_8);
    assertThat(errorMsg).contains("invalid input length for G1 point validation");
  }

  @Test
  public void testG2IsOnCurve_ValidPoint() {
    final byte[] input = Bytes.fromHexString(VALID_G2_POINT).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G2IsOnCurve(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isTrue();
  }

  @Test
  public void testG2IsOnCurve_InvalidPoint() {
    final byte[] input = Bytes.fromHexString(INVALID_G2_POINT_NOT_ON_CURVE).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G2IsOnCurve(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isFalse();
    String errorMsg = new String(error, 0, LibGnarkUtils.findFirstTrailingZeroIndex(error), UTF_8);
    assertThat(errorMsg).contains("invalid point: point is not on curve");
  }

  @Test
  public void testG1IsInSubGroup_ValidPoint() {
    final byte[] input = Bytes.fromHexString(VALID_G1_POINT).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G1IsInSubGroup(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isTrue();
  }

  @Test
  @Ignore("generate a g1 point that is in subgroup but not on curve")
  public void testG1IsInSubGroup_NotInSubGroup() {
    final byte[] input = Bytes.fromHexString(G1_POINT_NOT_IN_SUBGROUP).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G1IsInSubGroup(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isFalse();
    String errorMsg = new String(error, 0, LibGnarkUtils.findFirstTrailingZeroIndex(error), UTF_8);
    assertThat(errorMsg).contains("invalid point: subgroup check failed");
  }

  @Test
  public void testG1IsInSubGroup_NotOnCurve() {
    final byte[] input = Bytes.fromHexString(INVALID_G1_POINT_NOT_ON_CURVE).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G1IsInSubGroup(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isFalse();
    String errorMsg = new String(error, 0, LibGnarkUtils.findFirstTrailingZeroIndex(error), UTF_8);
    assertThat(errorMsg).contains("invalid point: point is not on curve");
  }

  @Test
  public void testG2IsInSubGroup_ValidPoint() {
    final byte[] input = Bytes.fromHexString(VALID_G2_POINT).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G2IsInSubGroup(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isTrue();
  }

  @Test
  @Ignore("generate a g2 point that is not in subgroup")
  public void testG2IsInSubGroup_NotInSubGroup() {
    final byte[] input = Bytes.fromHexString(G2_POINT_NOT_IN_SUBGROUP).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G2IsInSubGroup(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isFalse();
    String errorMsg = new String(error, 0, LibGnarkUtils.findFirstTrailingZeroIndex(error), UTF_8);
    assertThat(errorMsg).contains("invalid point: subgroup check failed");
  }

  @Test
  public void testG2IsInSubGroup_NotOnCurve() {
    final byte[] input = Bytes.fromHexString(INVALID_G2_POINT_NOT_ON_CURVE).toArrayUnsafe();
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G2IsInSubGroup(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isFalse();
    String errorMsg = new String(error, 0, LibGnarkUtils.findFirstTrailingZeroIndex(error), UTF_8);
    assertThat(errorMsg).contains("invalid point: point is not on curve");
  }

  @Test
  public void testG1IsOnCurve_ZeroPoint() {
    // Test the point at infinity (all zeros) which should be on curve
    final byte[] input = new byte[128]; // All zeros
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G1IsOnCurve(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isTrue();
  }

  @Test
  public void testG2IsOnCurve_ZeroPoint() {
    // Test the point at infinity (all zeros) which should be on curve
    final byte[] input = new byte[256]; // All zeros  
    final byte[] error = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    
    boolean result = LibGnarkEIP2537.eip2537G2IsOnCurve(
        input, error, input.length, LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        
    assertThat(result).isTrue();
  }
}
