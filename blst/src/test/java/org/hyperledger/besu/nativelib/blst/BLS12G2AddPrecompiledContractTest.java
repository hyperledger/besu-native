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
package org.hyperledger.besu.nativelib.blst;

import com.google.common.io.CharStreams;
import org.apache.tuweni.bytes.Bytes;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;

@RunWith(Parameterized.class)
public class BLS12G2AddPrecompiledContractTest {

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
                BLS12G2AddPrecompiledContractTest.class.getResourceAsStream("g2_add.csv"), UTF_8))
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
    byte[] testInput = Bytes.fromHexString(this.input).toArrayUnsafe();
    final Bytes expectedComputation = Optional.ofNullable(expectedResult)
        .filter(expected -> !expected.isBlank())
        .map(Bytes::fromHexString)
        .orElse(Bytes.EMPTY);

    Bls12381.G2Result res = null;
    res = Bls12381.g2Add(testInput);

    if (res.optError().isPresent()) {
      assertThat(notes).isNotEmpty();
      assertThat(res.optError().get()).contains(notes);
      assertThat(res.g2Out()).isNull();
    } else {
      final Bytes actualComputation = Bytes.wrap(res.g2Out().padded());
      assertThat(actualComputation).isEqualTo(expectedComputation);
    }
  }
}
