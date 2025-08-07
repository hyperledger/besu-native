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
package org.hyperledger.besu.nativelib.secp256k1;


import com.google.common.io.CharStreams;
import org.apache.tuweni.bytes.Bytes;
import org.assertj.core.api.Assertions;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;

@RunWith(Parameterized.class)
public class Secp256K1JNIEcrecoverParameterizedTest {
  private static final int V_BASE = 27;

  @Parameterized.Parameter(0)
  public String input;

  @Parameterized.Parameter(1)
  public String expectedOutput;

  @Parameterized.Parameter(2)
  public String expectedStatus;

  @Parameterized.Parameter(3)
  public String error;

  @Parameterized.Parameter(4)
  public String notes;

  @Parameterized.Parameters
  public static Iterable<String[]> parameters() throws IOException {
    return CharStreams.readLines(
            new InputStreamReader(
                Secp256K1JNIEcrecoverParameterizedTest.class.getResourceAsStream("secp256k1ecrecover.csv"), UTF_8))
        .stream()
        .map(line -> line.split(",", 5))
        .collect(Collectors.toList());
  }

  @Test
  public void shouldCalculateSecP256K1EcrecoverFromCSV() {
    // Skip the header row
    if ("input".equals(input)) {
      return;
    }

    Assume.assumeTrue("secp256k1 native must be enabled", LibSecp256k1JNI.ENABLED);

    // Handle null input case
    if (input == null || input.isEmpty()) {
      return;
    }

    // Parse input: hash (32 bytes) + recovery_id (1 byte) + signature (64 bytes)
    byte[] inputBytes = Bytes.fromHexString(input).toArrayUnsafe();

    // Extract components from input
    byte[] hash = new byte[32];
    System.arraycopy(inputBytes, 0, hash, 0, 32);

    int recoveryId = (inputBytes[63] & 0xFF) - V_BASE;
    int siglen = inputBytes.length >= 128 ? 64 : inputBytes.length - 64;
    byte[] signature = new byte[siglen];
    System.arraycopy(inputBytes, 64, signature, 0, siglen);

    // Call ecrecover
    LibSecp256k1JNI.ECRecoverResult
        result = LibSecp256k1JNI.ecrecover(hash, signature, recoveryId);


    // Parse expected result
    Bytes expectedPublicKey = Bytes.fromHexString(expectedOutput);
    int expectedStatusInt = Integer.parseInt(expectedStatus);
    // Verify the result
    Assertions.assertThat(result.status())
        .as("Test case: %s", notes)
        .isEqualTo(expectedStatusInt);

    // For successful cases, verify we got a public key
    if (expectedStatusInt == 0) {
      System.err.println(Bytes.wrap(result.publicKey().get()).toHexString());
      Assertions.assertThat(result.publicKey())
          .as("Success case should have public key: %s", notes)
          .isPresent();
      Assertions.assertThat(result.publicKey().get())
          .as("Success case should have public key: %s", notes)
          .isEqualTo(expectedPublicKey.toArrayUnsafe());
      Assertions.assertThat(result.error())
          .as("Success case should have no error: %s", notes)
          .isEmpty();
    } else {
      // For failed cases, verify no public key and error present
      Assertions.assertThat(result.publicKey())
          .as("Failed case should have no public key: %s", notes)
          .isNotPresent();
      Assertions.assertThat(result.error())
          .as("Failed case should have error: %s", notes)
          .isPresent();
      Assertions.assertThat(result.error().get())
          .as("Failed case should have error: %s", notes)
          .isEqualTo(error);
    }
  }
}
