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
package org.hyperledger.besu.nativelib.constantine;

import com.google.common.io.CharStreams;
import org.apache.tuweni.bytes.Bytes;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class ConstantineEIP2537FpToG1Test {

    @Parameterized.Parameter(0)
    public String input;
    @Parameterized.Parameter(1)
    public String expectedResult;
    @Parameterized.Parameter(2)
    public String expectedGasUsed;
    @Parameterized.Parameter(3)
    public String notes;

    @Parameterized.Parameters
    public static Iterable<String[]> parameters() throws IOException {
        return CharStreams.readLines(
                        new InputStreamReader(
                                ConstantineEIP2537FpToG1Test.class.getResourceAsStream("/fp_to_g1.csv"), UTF_8))
                .stream()
                .map(line -> line.split(",", 4))
                .collect(Collectors.toList());
    }

    @Test
    public void shouldCalculate() {
        if ("input".equals(input)) {
            return;  // skip header row
        }

        byte[] inputBytes = Bytes.fromHexString(this.input).toArrayUnsafe();
        byte[] result = new byte[96];  // G1 element in BLS12-381 is 96 bytes

        int status = LibConstantineEIP2537.bls12381_mapFpToG1(result, result.length, inputBytes, inputBytes.length);

        Bytes expectedComputation = expectedResult == null ? null : Bytes.fromHexString(expectedResult);
        if (status != 0) {
            assertNotNull("Notes should not be empty", notes);
            assertNotEquals("Status should not be success", 0, status);
            assertArrayEquals("Result should be empty on failure", new byte[96], result);
        } else {
            Bytes actualComputation = Bytes.wrap(result);
            if (actualComputation.isZero()) actualComputation = Bytes.EMPTY;

            assertEquals("Computed result should match expected result", expectedComputation, actualComputation);
            assertTrue("Notes should be empty on success", notes.isEmpty());
        }
    }
}
