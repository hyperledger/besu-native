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

/**
 * The expected shared points were computed with an independent affine-arithmetic implementation
 * and cross-checked with BouncyCastle.
 */
@RunWith(Parameterized.class)
public class Secp256K1JNIEcdhParameterizedTest {

  @Parameterized.Parameter(0)
  public String privateKey;

  @Parameterized.Parameter(1)
  public String publicKey;

  @Parameterized.Parameter(2)
  public String expectedSharedPoint;

  @Parameterized.Parameter(3)
  public String expectedStatus;

  @Parameterized.Parameter(4)
  public String error;

  @Parameterized.Parameter(5)
  public String notes;

  @Parameterized.Parameters(name = "{5}")
  public static Iterable<String[]> parameters() throws IOException {
    return CharStreams.readLines(
            new InputStreamReader(
                Secp256K1JNIEcdhParameterizedTest.class.getResourceAsStream("secp256k1ecdh.csv"), UTF_8))
        .stream()
        .skip(1)
        .map(line -> line.split(",", 6))
        .collect(Collectors.toList());
  }

  @Test
  public void shouldCalculateSecP256K1EcdhFromCSV() {
    Assume.assumeTrue("secp256k1 native must be enabled", LibSecp256k1JNI.ENABLED);

    LibSecp256k1JNI.ECDHResult result =
        LibSecp256k1JNI.ecdh(
            Bytes.fromHexString(publicKey).toArrayUnsafe(),
            Bytes.fromHexString(privateKey).toArrayUnsafe());

    int expectedStatusInt = Integer.parseInt(expectedStatus);
    Assertions.assertThat(result.status()).as("Test case: %s", notes).isEqualTo(expectedStatusInt);

    if (expectedStatusInt == LibSecp256k1JNI.STATUS_SUCCESS) {
      Assertions.assertThat(result.sharedPoint())
          .as("Success case should have a shared point: %s", notes)
          .hasValueSatisfying(
              point ->
                  Assertions.assertThat(Bytes.wrap(point))
                      .isEqualTo(Bytes.fromHexString(expectedSharedPoint)));
      Assertions.assertThat(result.error())
          .as("Success case should have no error: %s", notes)
          .isEmpty();
    } else {
      Assertions.assertThat(result.sharedPoint())
          .as("Failed case should have no shared point: %s", notes)
          .isNotPresent();
      Assertions.assertThat(result.error())
          .as("Failed case should have an error: %s", notes)
          .hasValue(error);
    }
  }
}
