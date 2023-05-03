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

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.bytes.MutableBytes;
import org.junit.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class LibGnarkTest {

    @Test
    public void testHashZero() {
        byte[] output = new byte[Bytes32.SIZE];
        LibGnark.computeMimc(Bytes32.ZERO.toArrayUnsafe(), Bytes32.SIZE, output);
        assertThat(Bytes.wrap(output)).isEqualTo(Bytes.fromHexString("0x2c7298fd87d3039ffea208538f6b297b60b373a63792b4cd0654fdc88fd0d6ee"));
    }

    @Test
    public void testHashOne() {
        byte[] output = new byte[Bytes32.SIZE];
        LibGnark.computeMimc(Bytes32.leftPad(Bytes.of(1)).toArrayUnsafe(), Bytes32.SIZE, output);
        assertThat(Bytes.wrap(output)).isEqualTo(Bytes.fromHexString("0x27e5458b666ef581475a9acddbc3524ca252185cae3936506e65cda9c358222b"));
    }

    @Test
    public void testLongString() {
        MutableBytes input = MutableBytes.of(new byte[Bytes32.SIZE*16]);
        for (int i = 0; i < 16; i++) {
            input.set(Bytes32.SIZE*(i+1)-1,(byte) i);
        }
        byte[] output = new byte[Bytes32.SIZE];
        LibGnark.computeMimc(input.toArrayUnsafe(), input.size(), output);
        assertThat(Bytes.wrap(output)).isEqualTo(Bytes.fromHexString("0x145875dd085ea2fb9796333e55c9da80228eb321df0ca9a41ca64ba6fe90b167"));
    }
}