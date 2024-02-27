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
    public void testCommitCompressedZeroes() {
	Bytes input = Bytes.fromHexString("0x9002400000000000000000000000000000");
    Bytes result = Bytes.of(LibIpaMultipoint.commitAsCompressed(input.toArray()));
    assertThat(result).isEqualTo(Bytes.fromHexString("0xa0bf101a6e1c8e83c11bd203a582c7981b91097ec55cbd344ce09005c1f26d1922"));
    }

    @Test
    public void testCommitCompressedOnes() {
	Bytes input0 = Bytes.fromHexString("0x02400000000000000000000000000000");
	Bytes input1 = Bytes.fromHexString("0x01010101010101010101010101010101");
	Bytes input = Bytes.wrap(input0, input1, input1, input1, input1);
        Bytes result = Bytes.of(LibIpaMultipoint.commitAsCompressed(input.toArray()));
        assertThat(result).isEqualTo(Bytes32.fromHexString("0x54427497ffbee0d2511e14ddaf3497e9b5e8438ff17974d06918e0e8ebe8b61a"));
    }

    @Test
    public void testTrieKeyAdaptorCommitOnly() {
	Bytes constant = Bytes.fromHexString("0x02400000000000000000000000000000");
        // Example of passing address and trieIndex to pedersenHash.
        Bytes32 address = Bytes32.fromHexString("0xed3f9549040250ec5cdef31947e5213edee80ad2d5bba35c9e48246c5d9213d6");
        Bytes32 trieIndex = (Bytes32) Bytes32.fromHexString("0x1C4C6CE0115457AC1AB82968749EB86ED2D984743D609647AE88299989F91271").reverse();
        byte[] total = Bytes.wrap(constant, address, trieIndex).toArray();
        Bytes result = Bytes.of(LibIpaMultipoint.commit(total));
	Bytes expected = Bytes.fromHexString("0x2e50716b7d8c6d13d6005ea248f63f5a11ed63318cad38010f4bcb9a9c2e8b43bc1029fd6e6484bae410d6b5cb7d6223ce054c9d51ad28f76de4fbc6fd55bd73");
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void testCompressCommitTrieKey() {
	Bytes input = Bytes.fromHexString("0x2e50716b7d8c6d13d6005ea248f63f5a11ed63318cad38010f4bcb9a9c2e8b43bc1029fd6e6484bae410d6b5cb7d6223ce054c9d51ad28f76de4fbc6fd55bd73");
        Bytes result = Bytes.of(LibIpaMultipoint.toCompressed(input.toArray()));
	Bytes expected = input.slice(0, 32);
	assertThat(result).isEqualTo(expected);
    }

    @Test
    public void testTrieKeyAdaptor() {
	Bytes constant = Bytes.fromHexString("0x02400000000000000000000000000000");
        // Example of passing address and trieIndex to pedersenHash.
        Bytes32 address = Bytes32.fromHexString("0xed3f9549040250ec5cdef31947e5213edee80ad2d5bba35c9e48246c5d9213d6");
        Bytes32 trieIndex = (Bytes32) Bytes32.fromHexString("0x1C4C6CE0115457AC1AB82968749EB86ED2D984743D609647AE88299989F91271").reverse();
        byte[] total = Bytes.wrap(constant, address, trieIndex).toArray();
        // Bytes result = Bytes.of(LibIpaMultipoint.mapCommitmentToScalar(LibIpaMultipoint.commit(16, total)));
        Bytes result = Bytes.of(LibIpaMultipoint.commitAsCompressed(total));
        assertThat(result).isEqualTo(Bytes32.fromHexString("0x2e50716b7d8c6d13d6005ea248f63f5a11ed63318cad38010f4bcb9a9c2e8b43"));
    }

    @Test
    public void testCallLibraryCommit() {
        Bytes inHeader = Bytes.fromHexString("0xe1a0");
        Bytes inPayload = Bytes.fromHexString("0x0000fe0c00000000000000000000000000000000000000000000000000000000");
        Bytes input = Bytes.concatenate(inHeader, inPayload);
        Bytes result = Bytes.wrap(LibIpaMultipoint.commit(input.toArray()));
        Bytes exHeader = Bytes.fromHexString("0xb840");
        Bytes exPayload = Bytes.fromHexString("0x28f74745658eb9912b6bcfb0a58f68977d3324a5105e35b60169433ca6ba6c7089b10c9429d6893126084a1cca1c518e22106cf8b06c2c9f0c86f656f88d7f0c");
        Bytes expected = Bytes.concatenate(exHeader, exPayload);
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void testCallLibraryCommitAsCompressed() {
        Bytes inHeader = Bytes.fromHexString("0xe1a0");
        Bytes inPayload = Bytes.fromHexString("0x59d039a350f2f9c751a97ee39dd16235d410ac6945d2fd480b395a567a1fe300");
        Bytes input = Bytes.concatenate(inHeader, inPayload);
        Bytes result = Bytes.wrap(LibIpaMultipoint.commitAsCompressed(input.toArray()));
        Bytes exHeader = Bytes.fromHexString("0xa0");
        Bytes exPayload = Bytes.fromHexString("0x3337896554fd3960bef9a4d0ff658ee8ee470cf9ca88a3c807cbe128536c5c05");
        Bytes expected = Bytes.concatenate(exHeader, exPayload);
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void testCallLibraryWithManyElements() {
        Bytes element = Bytes.fromHexString("0x00ecc7e76c11ad699e887f96bff372b308836c14e22279c81265fb4130fe0c");
        Bytes[] arr = new Bytes[128];
        for (int i = 0; i < 128; i++) {
            arr[i] = element;
        }
        Bytes inHeader = Bytes.fromHexString("0xc21000");
        Bytes inPayload = Bytes.concatenate(arr);
        Bytes input = Bytes.concatenate(inHeader, inPayload);
        Bytes result = Bytes.wrap(LibIpaMultipoint.commit(input.toArray()));
        Bytes exHeader = Bytes.fromHexString("0xb840");
        Bytes exPayload = Bytes.fromHexString("0x0128b513cfb016d3d836b5fa4a8a1260395d4ca831d65027aa74b832d92e0d6d9beb8d5e42b78b99e4eb233e7eca6276c6f4bd235b35c091546e2a2119bc1455");
        Bytes expected = Bytes.concatenate(exHeader, exPayload);
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void testCallLibraryWithMaxElements() {
        Bytes32 element = Bytes32.fromHexString("0x5b04e049425e6cfee43ddb1d8d57e44dd0fe8eff862125d907f6747f56206f00");
        Bytes32[] arr = new Bytes32[256];
        for (int i = 0; i < 256; i++) {
            arr[i] = element;
        }
        Bytes inHeader = Bytes.fromHexString("0xc22100");
        Bytes inPayload = Bytes.concatenate(arr);
        Bytes input = Bytes.concatenate(inHeader, inPayload);
        Bytes result = Bytes.wrap(LibIpaMultipoint.commit(input.toArray()));
        Bytes exHeader = Bytes.fromHexString("0xb840");
        Bytes exPayload = Bytes.fromHexString("0xcfb8d6fe536dec3d72ae549a0b58c7d2d119e7dd58adb2663369275307cd5a1f8adafed4044dbdc9ba9fb4f7ea0e44ab14c1c47297633015d175d7dcaffeb843");
        Bytes expected = Bytes.concatenate(exHeader, exPayload);
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void testCallLibraryPedersenHash() {
        // Example of passing address and trieIndex to pedersenHash.
        Bytes header2 = Bytes.fromHexString("0x82");
	    Bytes input0 = Bytes.fromHexString("0x0240");
        Bytes header16 = Bytes.fromHexString("0x90");
        Bytes32 address = (Bytes32) Bytes32.fromHexString("0x003f9549040250ec5cdef31947e5213edee80ad2d5bba35c9e48246c5d9213d6");
        Bytes32 trieIndex = (Bytes32) Bytes32.fromHexString("0x004C6CE0115457AC1AB82968749EB86ED2D984743D609647AE88299989F91271").reverse();
        byte[] total = Bytes.concatenate(
            header2, input0,
            header16, address.slice(0, 16),
            header16, address.slice(16, 16),
            header16, trieIndex.slice(0, 16),
            header16, trieIndex.slice(16, 16)
        ).toArray();
        // Bytes result = Bytes.of(LibIpaMultipoint.mapCommitmentToScalar(LibIpaMultipoint.commit(16, total)));
        Bytes result = Bytes.of(LibIpaMultipoint.commitAsCompressed(total));
        Bytes exHeader = Bytes.fromHexString("0xa0");
        Bytes exPayload = Bytes32.fromHexString("0xff6e8f1877fd27f91772a4cec41d99d2f835d7320e929b8d509c5fa7ce095c51");
        Bytes expected = Bytes.concatenate(exHeader, exPayload);
        assertThat(result).isEqualTo(expected);
    }

    // @Test
    // public void testUpdateCommitmentSparseIdentityCommitment() {
    //     // Numbers and result is taken from: https://github.com/crate-crypto/rust-verkle/blob/bb5af2f2fe9788d49d2896b9614a3125f8227818/ffi_interface/src/lib.rs#L576
    //    // Identity element
    //    Bytes oldCommitment = Bytes.fromHexString("0x00000000000000000000000000000000000000000000000000000000000000000100000000000000000000000000000000000000000000000000000000000000");

    //    Bytes oldScalar1 = Bytes.fromHexString("0x0200000000000000000000000000000000000000000000000000000000000000");
    //    Bytes newScalar1 = Bytes.fromHexString("0x1300000000000000000000000000000000000000000000000000000000000000");
    //    Bytes index1 = Bytes.fromHexString("0x07");

    //    Bytes oldScalar2 = Bytes.fromHexString("0x0200000000000000000000000000000000000000000000000000000000000000");
    //    Bytes newScalar2 = Bytes.fromHexString("0x1100000000000000000000000000000000000000000000000000000000000000");
    //    Bytes index2 = Bytes.fromHexString("0x08");

    //    Bytes input = Bytes.concatenate(oldCommitment, oldScalar1, newScalar1, index1, oldScalar2, newScalar2, index2);

    //    Bytes result = Bytes.of(LibIpaMultipoint.updateCommitmentSparse(input.toArray()));

    //    assertThat(result).isEqualTo(Bytes.fromHexString("6cf7264f1fff79a21b1be098e66e2457f2cba14c36c33a794566f85be8e6c61dc2a29760223e7c568af4ca13a08535d3e66ba7e2dd1e053894f1fdccdc560a54"));
    //}

    //@Test
    //public void testUpdateCommitmentSparseNonIdentityCommitment() {
    //    // These values are taken from: https://github.com/crate-crypto/rust-verkle/blob/bb5af2f2fe9788d49d2896b9614a3125f8227818/ffi_interface/src/lib.rs#L494
    //    Bytes oldCommitment = Bytes.fromHexString("c2a169fe13aab966d6642801727c8534e40b355372890e18a9880f66b88e143a37fe18000aaf81d4536b64ec3266678c56baf81645d4cfd5133a908247ab8445");
    //    Bytes oldScalar1 = Bytes.fromHexString("0x0400000000000000000000000000000000000000000000000000000000000000");
    //    Bytes newScalar1 = Bytes.fromHexString("0x7f00000000000000000000000000000000000000000000000000000000000000");
    //    Bytes index1 = Bytes.fromHexString("0x01");

    //    Bytes oldScalar2 = Bytes.fromHexString("0x0900000000000000000000000000000000000000000000000000000000000000");
    //    Bytes newScalar2 = Bytes.fromHexString("0xff00000000000000000000000000000000000000000000000000000000000000");
    //    Bytes index2 = Bytes.fromHexString("0x02");

    //    Bytes input = Bytes.concatenate(oldCommitment, oldScalar1, newScalar1, index1, oldScalar2, newScalar2, index2);

    //    Bytes result = Bytes.of(LibIpaMultipoint.updateCommitmentSparse(input.toArray()));

    //    assertThat(result).isEqualTo(Bytes.fromHexString("2dd3bb69da79ecd91a74b188bfddc74827a995dec07e5308f8215f08d69e77330b11628c6d3313a7781b74850e64cb6ac706290da79e56ff311a10214d14dc36"));

    //}
}

