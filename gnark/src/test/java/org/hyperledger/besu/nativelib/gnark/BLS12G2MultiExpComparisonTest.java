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

import com.google.common.base.Stopwatch;
import com.google.common.io.CharStreams;
import org.apache.tuweni.bytes.Bytes;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.io.InputStreamReader;
import java.time.Duration;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.hyperledger.besu.nativelib.gnark.LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_ERROR_BYTES;
import static org.hyperledger.besu.nativelib.gnark.LibGnarkEIP2537.EIP2537_PREALLOCATE_FOR_RESULT_BYTES;

@Ignore(value = "This is exploratory to discover performance on various platforms")
@RunWith(Parameterized.class)
public class BLS12G2MultiExpComparisonTest {
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
                BLS12G2MultiExpComparisonTest.class
                    .getResourceAsStream("g2_multiexp_pair_comparison.csv"),
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
    final byte[] input = Bytes.fromHexString(this.input).toArrayUnsafe();

    final byte[] output1 = new byte[EIP2537_PREALLOCATE_FOR_RESULT_BYTES];
    final byte[] error1 = new byte[EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    int ret1 = 0;

    final byte[] output2 = new byte[EIP2537_PREALLOCATE_FOR_RESULT_BYTES];
    final byte[] error2 = new byte[EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    int ret2 = 0;

    final byte[] output3 = new byte[EIP2537_PREALLOCATE_FOR_RESULT_BYTES];
    final byte[] error3 = new byte[EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    int ret3 = 0;

    Stopwatch timer = Stopwatch.createStarted();
    for(int i = 0; i< 1000; i++) {
      // mul/add loop:
      ret1 = LibGnarkEIP2537.eip2537blsG2MultiExp(input, output1, error1, input.length,
          EIP2537_PREALLOCATE_FOR_RESULT_BYTES, EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
    }

    Duration muladd = timer.elapsed();
    timer.reset().start();

    for(int i = 0; i< 1000; i++) {
      ret2 = LibGnarkEIP2537.eip2537blsG2MultiExpParallel(input, output2, error2, input.length,
          EIP2537_PREALLOCATE_FOR_RESULT_BYTES, EIP2537_PREALLOCATE_FOR_ERROR_BYTES,
          /*degreeOfMSMParallelism = 1*/
          1);
    }
    Duration singleTaskPip = timer.elapsed();
    timer.reset().start();

    for(int i = 0; i< 1000; i++) {
      ret3 = LibGnarkEIP2537.eip2537blsG2MultiExpParallel(input, output3, error3, input.length,
          EIP2537_PREALLOCATE_FOR_RESULT_BYTES, EIP2537_PREALLOCATE_FOR_ERROR_BYTES,
          /* degreeOfMSMParallelism uncapped*/
          0);
    }
    Duration uncappedPip = timer.elapsed();

    System.err.println(
        String.format(
            "G2 MSM ret %d \tpair count: %d \tmulAdd: %d ms \t1task: %d ms \tuncapped:%d ms",
            ret1, input.length / 288,
            muladd.toMillis(),
            singleTaskPip.toMillis(),
            uncappedPip.toMillis()
        )
    );

    final Bytes expectedComputation =
        expectedResult == null ? null : Bytes.fromHexString(expectedResult);
    String error1Str = new String(error1);
    String error2Str = new String(error2);
    String error3Str = new String(error3);
    assertThat(error1Str).isEqualTo(error2Str);
    assertThat(error2Str).isEqualTo(error3Str);
    assertThat(ret1).isEqualTo(ret2);
    assertThat(ret2).isEqualTo(ret3);

    if (error1Str.isEmpty()) {
      assertThat(error1Str).isEqualTo(notes);
      assertThat(error2Str).isEqualTo(notes);
      assertThat(error3Str).isEqualTo(notes);
    } else {
      final Bytes actualComputation1 = Bytes.wrap(output1, 0, 256);
      final Bytes actualComputation2 = Bytes.wrap(output2, 0, 256);
      final Bytes actualComputation3 = Bytes.wrap(output3, 0, 256);
      assertThat(actualComputation1).isEqualTo(expectedComputation);
      assertThat(actualComputation2).isEqualTo(expectedComputation);
      assertThat(actualComputation3).isEqualTo(expectedComputation);
      assertThat(notes).isEmpty();
    }
  }
}
