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

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import com.google.common.base.Stopwatch;
import com.google.common.collect.Streams;
import com.google.common.io.CharStreams;
import com.sun.jna.ptr.IntByReference;
import org.apache.tuweni.bytes.Bytes;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

@RunWith(Parameterized.class)
public class BLS12PairingPrecompiledContractTest {
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
    return
        Streams.concat(
            CharStreams.readLines(
                new InputStreamReader(
                    BLS12PairingPrecompiledContractTest.class.getResourceAsStream("pairing.csv"),
                    UTF_8))
                .stream(),
            CharStreams.readLines(
                new InputStreamReader(
                    BLS12PairingPrecompiledContractTest.class.getResourceAsStream(
                        "invalid_subgroup_for_pairing.csv"),
                    UTF_8))
                .stream())
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

    int res = -1;
    Stopwatch timer = Stopwatch.createStarted();
    for(int i = 0; i < 100; i++) {
      input = Bytes.fromHexString(this.input).toArrayUnsafe();
      output = new byte[LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_RESULT_BYTES];
      res = LibGnarkEIP2537.eip2537blsPairing(input, output, input.length, output.length);
    }
    System.err.println("time taken for 100x gnark pairing: " + timer);

    if (res != 1) {
      var errBytes = Bytes.wrap(output);
      // trim trailing zeros from output error response and convert to String:
      var err = new String(errBytes
          .slice(0, errBytes.size() - errBytes.numberOfTrailingZeroBytes())
          .toArrayUnsafe());
      assertThat(err).isEqualTo(notes);
    } else {
      final Bytes expectedComputation =
          expectedResult == null ? null : Bytes.fromHexString(expectedResult);

      final Bytes actualComputation = Bytes.wrap(output, 0, 32);
      assertThat(actualComputation).isEqualTo(expectedComputation);
    }
  }
}
