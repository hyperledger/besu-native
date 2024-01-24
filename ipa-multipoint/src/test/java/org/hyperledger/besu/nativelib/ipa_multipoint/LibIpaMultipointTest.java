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
        Bytes32 input = Bytes32.fromHexString("0x0cfe0000");
        Bytes32 result = Bytes32.wrap(LibIpaMultipoint.commit(input.toArray()));
        Bytes32 expected = Bytes32.fromHexString("0x11169fb6b9dab0b5984ce0b02c9f2c9a3a5adf6f9a95b597bca42ac2a8d8e89f");
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void testCallLibraryCommitRoot() {
        Bytes32 input = Bytes32.fromHexString("0x00e31f7a565a390b48fdd24569ac10d43562d19de37ea951c7f9f250a339d059");
        Bytes32 result = Bytes32.wrap(LibIpaMultipoint.commitRoot(input.toArray()));
        Bytes32 expected = Bytes32.fromHexString("0x3337896554fd3960bef9a4d0ff658ee8ee470cf9ca88a3c807cbe128536c5c05");
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void testCallLibraryWithManyElements() {
        Bytes32 element = Bytes32.fromHexString("0x0cfe3041fb6512c87922e2146c8308b372f3bf967f889e69ad116ce7c7ec00");
        Bytes32[] arr = new Bytes32[128];
        for (int i = 0; i < 128; i++) {
            arr[i] = element;
        }
        Bytes input = Bytes.concatenate(arr);
        Bytes32 result = Bytes32.wrap(LibIpaMultipoint.commit(input.toArray()));
        Bytes32 expected = Bytes32.fromHexString("0x1b8a1c8c25323f9a58d9221b521f9618e78bb253866de6a3d1c16398678dfa26");
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void testCallLibraryWithMaxElements() {
        Bytes32 element = Bytes32.fromHexString("0x006f20567f74f607d9252186ff8efed04de4578d1ddb3de4fe6c5e4249e0045b");
        Bytes32[] arr = new Bytes32[256];
        for (int i = 0; i < 256; i++) {
            arr[i] = element;
        }
        Bytes input = Bytes.concatenate(arr);
        Bytes32 result = Bytes32.wrap(LibIpaMultipoint.commit(input.toArray()));
        Bytes32 expected = Bytes32.fromHexString("0x148badc53042581c95e71f21b2b85826bc2f4088e617cd18f488ab664af1d043");
        assertThat(result).isEqualTo(expected);
    }

    @Test
    public void testCallLibraryPedersenHash() {
        // Example of passing address and trieIndex to pedersenHash.
        Bytes32 address = Bytes32.fromHexString("0x003f9549040250ec5cdef31947e5213edee80ad2d5bba35c9e48246c5d9213d6");
        Bytes32 trieIndex = Bytes32.fromHexString("0x004C6CE0115457AC1AB82968749EB86ED2D984743D609647AE88299989F91271");
        byte[] total = Bytes.wrap(address, trieIndex).toArray();
        Bytes result = Bytes.of(LibIpaMultipoint.pedersenHash(total));
        assertThat(result).isEqualTo(Bytes32.fromHexString("0xbe9401ae598470e73d284279d01c8b49bf88565b14cb1a7ae829dbd78c3a5018"));
    }
}
