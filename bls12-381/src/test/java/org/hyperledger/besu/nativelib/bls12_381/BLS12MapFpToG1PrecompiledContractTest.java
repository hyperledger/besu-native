/*
 * Copyright ConsenSys AG.
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
package org.hyperledger.besu.nativelib.bls12_381;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import com.google.common.base.Stopwatch;
import com.google.common.io.CharStreams;
import com.sun.jna.ptr.IntByReference;
import org.apache.tuweni.bytes.Bytes;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class BLS12MapFpToG1PrecompiledContractTest {
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
                BLS12MapFpToG1PrecompiledContractTest.class.getResourceAsStream("fp_to_g1.csv"),
                UTF_8))
        .stream()
        .map(line -> line.split(",", 4))
        .collect(Collectors.toList());
  }

  @Test
  public void shouldCalculate() {
    if ("input".equals(input)) {
      // skip the header row
      return;
    }
    byte[] input = null;
    byte[] output = null;
    final IntByReference outputLength = new IntByReference();
    byte[] error = null;
    final IntByReference errorLength = new IntByReference();
    Stopwatch timer = Stopwatch.createStarted();
    for(int i = 0; i < 100; i++) {
      input = Bytes.fromHexString(this.input).toArrayUnsafe();
      output = new byte[LibEthPairings.EIP2537_PREALLOCATE_FOR_RESULT_BYTES];
      error = new byte[LibEthPairings.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
      LibEthPairings.eip2537_perform_operation(LibEthPairings.BLS12_MAP_FP_TO_G1_OPERATION_RAW_VALUE,
          input, input.length, output, outputLength, error, errorLength);
    }
    System.err.println("time taken for 100x rust FpToG1: " + timer);

    final Bytes expectedComputation =
        expectedResult == null ? null : Bytes.fromHexString(expectedResult);
    if (errorLength.getValue() > 0) {
      assertThat(new String(error, 0, errorLength.getValue(), UTF_8)).contains(notes);
      assertThat(outputLength.getValue()).isZero();
    } else {
      final Bytes actualComputation = Bytes.wrap(output, 0, outputLength.getValue());
      assertThat(actualComputation).isEqualTo(expectedComputation);
    }
  }
}
