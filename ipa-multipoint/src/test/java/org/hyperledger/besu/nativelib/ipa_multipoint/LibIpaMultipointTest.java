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
package org.hyperledger.besu.nativelib.ipa_multipoint;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.*;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.bytes.Bytes32;
import org.hyperledger.besu.nativelib.ipamultipoint.LibIpaMultipoint;

public class LibIpaMultipointTest {

    @Test
    public void testCallLibrary() {
        Bytes32 input = Bytes32.fromHexString("0x0000fe0c00000000000000000000000000000000000000000000000000000000");
        Bytes result = Bytes.wrap(LibIpaMultipoint.commit(input.toArray()));
        Bytes expected = Bytes.fromHexString("0x0c7f8df856f6860c9f2c6cb0f86c10228e511cca1c4a08263189d629940cb189706cbaa63c436901b6355e10a524337d97688fa5b0cf6b2b91b98e654547f728");
        assertThat(result).isEqualTo(expected.reverse());
    }

    @Test
    public void testCallLibraryCommitRoot() {
        Bytes32 input = Bytes32.fromHexString("0x59d039a350f2f9c751a97ee39dd16235d410ac6945d2fd480b395a567a1fe300");
        Bytes32 result = Bytes32.wrap(LibIpaMultipoint.commitRoot(input.toArray()));
        Bytes32 expected = Bytes32.fromHexString("0x3337896554fd3960bef9a4d0ff658ee8ee470cf9ca88a3c807cbe128536c5c05");
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void testCallLibraryWithManyElements() {
        Bytes32 element = Bytes32.fromHexString("0x00ecc7e76c11ad699e887f96bff372b308836c14e22279c81265fb4130fe0c00");
        Bytes32[] arr = new Bytes32[128];
        for (int i = 0; i < 128; i++) {
            arr[i] = element;
        }
        Bytes input = Bytes.concatenate(arr);
        Bytes result = Bytes.wrap(LibIpaMultipoint.commit(input.toArray()));
        Bytes expected = Bytes.fromHexString("0x0128b513cfb016d3d836b5fa4a8a1260395d4ca831d65027aa74b832d92e0d6d9beb8d5e42b78b99e4eb233e7eca6276c6f4bd235b35c091546e2a2119bc1455");
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void testCallLibraryWithMaxElements() {
        Bytes32 element = Bytes32.fromHexString("0x5b04e049425e6cfee43ddb1d8d57e44dd0fe8eff862125d907f6747f56206f00");
        Bytes32[] arr = new Bytes32[256];
        for (int i = 0; i < 256; i++) {
            arr[i] = element;
        }
        Bytes input = Bytes.concatenate(arr);
        Bytes result = Bytes.wrap(LibIpaMultipoint.commit(input.toArray()));
        Bytes expected = Bytes.fromHexString("0xcfb8d6fe536dec3d72ae549a0b58c7d2d119e7dd58adb2663369275307cd5a1f8adafed4044dbdc9ba9fb4f7ea0e44ab14c1c47297633015d175d7dcaffeb843");
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void testCallLibraryPedersenHash() {
        // Example of passing address and trieIndex to pedersenHash.
        Bytes32 address = Bytes32.fromHexString("0x003f9549040250ec5cdef31947e5213edee80ad2d5bba35c9e48246c5d9213d6");
        Bytes32 trieIndex = Bytes32.fromHexString("0x004C6CE0115457AC1AB82968749EB86ED2D984743D609647AE88299989F91271");
        byte[] total = Bytes.wrap(address, trieIndex).toArray();
        Bytes result = Bytes.of(LibIpaMultipoint.pedersenHash(total));
        assertThat(result).isEqualTo(Bytes32.fromHexString("0xff6e8f1877fd27f91772a4cec41d99d2f835d7320e929b8d509c5fa7ce095c51"));
    }

    @Test
    public void testUpdateCommitmentSparse() {
        // Numbers and result is taken from: https://github.com/crate-crypto/rust-verkle/blob/bb5af2f2fe9788d49d2896b9614a3125f8227818/ffi_interface/src/lib.rs#L576
        // Identity element
        byte[] old_commitment = new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

        byte[] old_scalar_new_scalar_index = new byte[]{2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                19, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 7,
                2, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                17, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 8};
        Bytes input = Bytes.concatenate(Bytes.of(old_commitment), Bytes.of(old_scalar_new_scalar_index));
        Bytes result = Bytes.of(LibIpaMultipoint.updateCommitmentSparse(input.toArray()));

        assertThat(result).isEqualTo(Bytes.fromHexString("6cf7264f1fff79a21b1be098e66e2457f2cba14c36c33a794566f85be8e6c61dc2a29760223e7c568af4ca13a08535d3e66ba7e2dd1e053894f1fdccdc560a54"));
    }

}