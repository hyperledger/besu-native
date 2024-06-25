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
 */
package org.hyperledger.besu.nativelib.bls12_381;

import static org.assertj.core.api.Assertions.assertThat;

import com.sun.jna.ptr.IntByReference;
import org.apache.tuweni.bytes.Bytes;
import org.junit.Test;

public class AltBN128PairingPrecompiledContractTest {

  @Test
  public void compute_validPoints() {
    final Bytes g1Point0 =
        Bytes.concatenate(
            Bytes.fromHexString(
                "0x0000000000000000000000000000000000000000000000000000000000000001"),
            Bytes.fromHexString(
                "0x0000000000000000000000000000000000000000000000000000000000000002"));
    final Bytes g2Point0 =
        Bytes.concatenate(
            Bytes.fromHexString(
                "0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"),
            Bytes.fromHexString(
                "0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"),
            Bytes.fromHexString(
                "0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"),
            Bytes.fromHexString(
                "0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"));
    final Bytes g1Point1 =
        Bytes.concatenate(
            Bytes.fromHexString(
                "0x0000000000000000000000000000000000000000000000000000000000000001"),
            Bytes.fromHexString(
                "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"));
    final Bytes g2Point1 =
        Bytes.concatenate(
            Bytes.fromHexString(
                "0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2"),
            Bytes.fromHexString(
                "0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed"),
            Bytes.fromHexString(
                "0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b"),
            Bytes.fromHexString(
                "0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa"));

    final byte[] input = Bytes.concatenate(g1Point0, g2Point0, g1Point1, g2Point1).toArrayUnsafe();
    final byte[] output = new byte[LibEthPairings.EIP2537_PREALLOCATE_FOR_RESULT_BYTES];
    final IntByReference outputLength = new IntByReference();
    final byte[] error = new byte[LibEthPairings.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    final IntByReference errorLength = new IntByReference();
    LibEthPairings.eip196_perform_operation(
        LibEthPairings.EIP196_PAIR_OPERATION_RAW_VALUE,
        input,
        input.length,
        output,
        outputLength,
        error,
        errorLength);

    assertThat(errorLength.getValue()).isEqualTo(0);
    assertThat(output[outputLength.getValue() - 1]).isEqualTo((byte) 1);
  }

  @Test
  public void compute_invalidPointsOutsideSubgroupG2() {
    final Bytes g1Point0 =
        Bytes.concatenate(
            Bytes.fromHexString(
                "0x0000000000000000000000000000000000000000000000000000000000000001"),
            Bytes.fromHexString(
                "0x0000000000000000000000000000000000000000000000000000000000000002"));
    final Bytes g2Point0 =
        Bytes.concatenate(
            Bytes.fromHexString(
                "0x1382cd45e5674247f9c900b5c6f6cabbc189c2fabe2df0bf5acd84c97818f508"),
            Bytes.fromHexString(
                "0x1246178655ab8f2f26956b189894b7eb93cd4215b9937e7969e44305f80f521e"),
            Bytes.fromHexString(
                "0x08331c0a261a74e7e75db1232956663cbc88110f726159c5cba1857ecd03fa64"),
            Bytes.fromHexString(
                "0x1fbf8045ce3e79b5cde4112d38bcd0efbdb1295d2eefdf58151ae309d7ded7db"));
    final Bytes g1Point1 =
        Bytes.concatenate(
            Bytes.fromHexString(
                "0x0000000000000000000000000000000000000000000000000000000000000001"),
            Bytes.fromHexString(
                "0x30644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45"));
    final Bytes g2Point1 =
        Bytes.concatenate(
            Bytes.fromHexString(
                "0x1382cd45e5674247f9c900b5c6f6cabbc189c2fabe2df0bf5acd84c97818f508"),
            Bytes.fromHexString(
                "0x1246178655ab8f2f26956b189894b7eb93cd4215b9937e7969e44305f80f521e"),
            Bytes.fromHexString(
                "0x08331c0a261a74e7e75db1232956663cbc88110f726159c5cba1857ecd03fa64"),
            Bytes.fromHexString(
                "0x1fbf8045ce3e79b5cde4112d38bcd0efbdb1295d2eefdf58151ae309d7ded7db"));

    final byte[] input = Bytes.concatenate(g1Point0, g2Point0, g1Point1, g2Point1).toArrayUnsafe();
    final byte[] output = new byte[LibEthPairings.EIP2537_PREALLOCATE_FOR_RESULT_BYTES];
    final IntByReference outputLength = new IntByReference();
    final byte[] error = new byte[LibEthPairings.EIP2537_PREALLOCATE_FOR_ERROR_BYTES];
    final IntByReference errorLength = new IntByReference();
    LibEthPairings.eip196_perform_operation(
        LibEthPairings.EIP196_PAIR_OPERATION_RAW_VALUE,
        input,
        input.length,
        output,
        outputLength,
        error,
        errorLength);

    // assert there is an error
    assertThat(errorLength.getValue()).isNotEqualTo(0);
    String errorString = new String(error, 0, errorLength.getValue());
    assertThat(errorString).isEqualTo("invalid input parameters, G2 point is not in the expected subgroup");
    // assert there is no output
    assertThat(outputLength.getValue()).isEqualTo(0);
  }
}
