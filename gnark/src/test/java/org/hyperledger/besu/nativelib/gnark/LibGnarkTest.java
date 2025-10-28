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
package org.hyperledger.besu.nativelib.gnark;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.apache.tuweni.bytes.MutableBytes;
import org.junit.Test;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class LibGnarkTest {

    @Test
    public void testHashZeroBn254() {
        byte[] output = new byte[Bytes32.SIZE];
        LibGnark.computeMimcBn254(Bytes32.ZERO.toArrayUnsafe(), Bytes32.SIZE, output);
        assertThat(Bytes.wrap(output)).isEqualTo(Bytes.fromHexString("0x2c7298fd87d3039ffea208538f6b297b60b373a63792b4cd0654fdc88fd0d6ee"));
    }

    @Test
    public void testHashOneBn254() {
        byte[] output = new byte[Bytes32.SIZE];
        LibGnark.computeMimcBn254(Bytes32.leftPad(Bytes.of(1)).toArrayUnsafe(), Bytes32.SIZE, output);
        assertThat(Bytes.wrap(output)).isEqualTo(Bytes.fromHexString("0x27e5458b666ef581475a9acddbc3524ca252185cae3936506e65cda9c358222b"));
    }

    @Test
    public void testLongStringBn254() {
        MutableBytes input = MutableBytes.of(new byte[Bytes32.SIZE*16]);
        for (int i = 0; i < 16; i++) {
            input.set(Bytes32.SIZE*(i+1)-1,(byte) i);
        }
        byte[] output = new byte[Bytes32.SIZE];
        LibGnark.computeMimcBn254(input.toArrayUnsafe(), input.size(), output);
        assertThat(Bytes.wrap(output)).isEqualTo(Bytes.fromHexString("0x145875dd085ea2fb9796333e55c9da80228eb321df0ca9a41ca64ba6fe90b167"));
    }

    @Test
    public void testHashZeroBls12377() {
        byte[] output = new byte[Bytes32.SIZE];
        LibGnark.computeMimcBls12377(Bytes32.ZERO.toArrayUnsafe(), Bytes32.SIZE, output);
        assertThat(Bytes.wrap(output)).isEqualTo(Bytes.fromHexString("0x0134373b65f439c874734ff51ea349327c140cde2e47a933146e6f9f2ad8eb17"));
    }

    @Test
    public void testHashOneBls12377() {
        byte[] output = new byte[Bytes32.SIZE];
        LibGnark.computeMimcBls12377(Bytes32.leftPad(Bytes.of(1)).toArrayUnsafe(), Bytes32.SIZE, output);
        assertThat(Bytes.wrap(output)).isEqualTo(Bytes.fromHexString("0x0d962bab9f4e4213383f25abc12d6ee78855fff118c94ca4352032b802ef8b87"));
    }

    @Test
    public void testLongStringBls12377() {
        MutableBytes input = MutableBytes.of(new byte[Bytes32.SIZE*16]);
        for (int i = 0; i < 16; i++) {
            input.set(Bytes32.SIZE*(i+1)-1,(byte) i);
        }
        byte[] output = new byte[Bytes32.SIZE];
        LibGnark.computeMimcBls12377(input.toArrayUnsafe(), input.size(), output);
        assertThat(Bytes.wrap(output)).isEqualTo(Bytes.fromHexString("0x12900ae41a010e54e3b1ed95efa39071d357ff642aeedd30a2c4e13250409662"));
    }

    @Test
    public void testHashZeroKoalabear() {
        byte[] output = new byte[Bytes32.SIZE];
        LibGnark.computePoseidon2Koalabear(Bytes32.ZERO.toArrayUnsafe(), Bytes32.SIZE, output);
        assertThat(Bytes.wrap(output)).isEqualTo(Bytes.fromHexString("0x225471e76dca970375f18cc4222539bf1893f40b2c28b7d62119af207704c426"));
    }

    @Test
    public void testHashOneKoalabear() {
        byte[] output = new byte[Bytes32.SIZE];
        LibGnark.computePoseidon2Koalabear(Bytes32.leftPad(Bytes.of(1)).toArrayUnsafe(), Bytes32.SIZE, output);
        assertThat(Bytes.wrap(output)).isEqualTo(Bytes.fromHexString("0x55c8f679114a34760e97b1b707c95e0250bcb1c851d0341a226324d957047cc1"));
    }

    @Test
    public void testLongStringKoalabear() {
        MutableBytes input = MutableBytes.of(new byte[Bytes32.SIZE*16]);
        for (int i = 0; i < 16; i++) {
            input.set(Bytes32.SIZE*(i+1)-1,(byte) i);
        }
        byte[] output = new byte[Bytes32.SIZE];
        LibGnark.computePoseidon2Koalabear(input.toArrayUnsafe(), input.size(), output);
        assertThat(Bytes.wrap(output)).isEqualTo(Bytes.fromHexString("0x5289c51f652faf00651f03ac563afb080cbcb3797897ecb13d68f7c027b7e029"));
    }


}