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

import org.apache.tuweni.bytes.Bytes;
import org.hyperledger.besu.nativelib.ipamultipoint.LibIpaMultipoint;
import org.junit.BeforeClass;
import org.junit.Test;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.assertj.core.api.AssertionsForClassTypes.assertThat;

public class LibIpaMultipointTest {

  @BeforeClass
  public static void setUp() {
    Path buildPath = Paths.get(LibIpaMultipointTest.class.getProtectionDomain().getCodeSource().getLocation().getFile()).getParent().getParent().getParent();
    File macFile = new File(buildPath.resolve("darwin/lib").toFile(), "libipa_multipoint_jni.dylib");
    File linuxFile = new File(buildPath.resolve("linux-gnu-x86_64/lib").toFile(), "libipa_multipoint_jni.so");
    File linuxArmFile = new File(buildPath.resolve("linux-gnu-aarch64/lib").toFile(), "libipa_multipoint_jni.so");
    if (linuxFile.exists()) {
      System.load(linuxFile.getAbsolutePath());
    } else if (linuxArmFile.exists()) {
        System.load(linuxArmFile.getAbsolutePath());
    } else if (macFile.exists()) {
      System.load(macFile.getAbsolutePath());
    } else {
      throw new RuntimeException("could not setup jni path for test");
    }
  }

  @Test
  public void testCallLibrary() {
    Bytes input = Bytes.fromHexString("0x0cfe3041fb6512c87922e2146c8308b372f3bf967f889e69ad116ce7c7ec840cfe3041fb6512c87922e2146c8308b372f3bf967f889e69ad116ce7c7ec840cfe3041fb6512c87922e2146c8308b372f3bf967f889e69ad116ce7c7ec840cfe3041fb6512c87922e2146c8308b372f3bf967f889e69ad116ce7c7ec84");
    byte[] result = LibIpaMultipoint.commit(input.toArrayUnsafe(), input.toArrayUnsafe(), input.toArrayUnsafe(), input.toArrayUnsafe());
    assertThat(Bytes.wrap(result)).isEqualTo(Bytes.fromHexString("0xc70a1e0077e1fff6702f2bde0cccf1bf5915d4c5ab73c33ea5e75b6f703d2346aa7aa373cd07fdf684282c11a7f7623b6e67d2b65862ca0011e2415726c87415d07ada26afff5e6be8066c57228e78399cb3af7490f4de739eef0191907eca0d9ba47aec3457f0fab28324061ec27508e29b067acb3a97fbb43dea61a376f73b"));
  }
}
