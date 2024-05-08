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
package org.hyperledger.besu.nativelib.gnark;

import com.google.common.io.CharStreams;
import com.sun.jna.ptr.IntByReference;
import org.apache.tuweni.bytes.Bytes;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(Parameterized.class)
public class BLS12G1AddPrecompiledContractTest {

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
                BLS12G1AddPrecompiledContractTest.class.getResourceAsStream("g1_add.csv"), UTF_8))
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
    final ByteBuffer input = ByteBuffer.wrap(
        Bytes.fromHexString(this.input).toArrayUnsafe());

    final ByteBuffer output = ByteBuffer.allocateDirect(
        LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_RESULT_BYTES);

    int res = LibGnarkEIP2537.eip2537blsG1Add(
        input,
        output, input.capacity(), output.capacity());

    if (res != 1) {
      var errBytes = Bytes.wrapByteBuffer(output);
      // trim trailing zeros from output error response and convert to String:
      var err = new String(errBytes
          .slice(0, errBytes.size() - errBytes.numberOfTrailingZeroBytes())
          .toArrayUnsafe());
      assertThat(err).isEqualTo(notes);
    } else {
      final Bytes expectedComputation =
          expectedResult == null ? null : Bytes.fromHexString(expectedResult);

      final Bytes actualComputation = Bytes.wrapByteBuffer(output, 0, 128);
      assertThat(actualComputation).isEqualTo(expectedComputation);
    }
  }
}
