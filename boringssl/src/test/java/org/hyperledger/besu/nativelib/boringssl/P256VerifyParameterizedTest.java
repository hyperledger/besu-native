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

import com.google.common.io.CharStreams;
import org.apache.tuweni.bytes.Bytes;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(Parameterized.class)
public class P256VerifyParameterizedTest {

    @Parameterized.Parameter(0)
    public String input;

    @Parameterized.Parameter(1)
    public String expectedStatus;

    @Parameterized.Parameter(2)
    public String expectedMessage;

    @Parameterized.Parameter(3)
    public String notes;

    @Parameterized.Parameters
    public static Iterable<String[]> parameters() throws IOException {
        return CharStreams.readLines(
                new InputStreamReader(
                        P256VerifyParameterizedTest.class.getResourceAsStream("p256_verify.csv"), UTF_8))
                .stream()
                .map(line -> line.split(",", 7))
                .collect(Collectors.toList());
    }

    @Test
    public void shouldCalculateP256VerifyFromCSV() {
        // Skip the header row
        if ("input".equals(input)) {
            return;
        }

        Assume.assumeTrue("P256Verify must be enabled", BoringSSLPrecompiles.ENABLED);


        // Handle null input case
        if (input == null || input.isEmpty()) {
            BoringSSLPrecompiles.P256VerifyResult result = BoringSSLPrecompiles.p256Verify(null, 0);
            int expectedStatusInt = Integer.parseInt(expectedStatus);
            assertThat(result.status).as("Test case: %s", notes).isEqualTo(expectedStatusInt);
            if (!expectedMessage.isEmpty()) {
                assertThat(result.error).as("Error message for test case: %s", notes).isEqualTo(expectedMessage);
            }
            return;
        }

        // Call P256 verify
        byte[] inputBytes = Bytes.fromHexString(input).toArrayUnsafe();
        BoringSSLPrecompiles.P256VerifyResult
            result = BoringSSLPrecompiles.p256Verify(inputBytes, inputBytes.length);

        // Parse expected status
        int expectedStatusInt = Integer.parseInt(expectedStatus);

        // Verify the result
        assertThat(result.status)
            .as("Test case: %s", notes)
            .isEqualTo(expectedStatusInt);

        // Verify error message if expected
        if (!expectedMessage.isEmpty()) {
            assertThat(result.error)
                .as("Error message for test case: %s", notes)
                .isEqualTo(expectedMessage);
        } else {
            // For successful cases, message should be empty
            assertThat(result.error)
                .as("Success case should have empty message: %s", notes)
                .isEmpty();
        }
    }
}
