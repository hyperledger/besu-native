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
        Bytes32 result = Bytes32.wrap(LibIpaMultipoint.commit(input.toArray()));
        Bytes32 expected = Bytes32.fromHexString("0x11169fb6b9dab0b5984ce0b02c9f2c9a3a5adf6f9a95b597bca42ac2a8d8e89f");
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
        Bytes32 result = Bytes32.wrap(LibIpaMultipoint.commit(input.toArray()));
        Bytes32 expected = Bytes32.fromHexString("0x26fa8d679863c1d1a3e66d8653b28be718961f521b22d9589a3f32258c1c8a1b");
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
        Bytes32 result = Bytes32.wrap(LibIpaMultipoint.commit(input.toArray()));
        Bytes32 expected = Bytes32.fromHexString("0x43d0f14a66ab88f418cd17e688402fbc2658b8b2211fe7951c584230c5ad8b14");
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
}
