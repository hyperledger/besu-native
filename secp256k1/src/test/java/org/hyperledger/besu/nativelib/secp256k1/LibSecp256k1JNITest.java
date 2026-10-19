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
package org.hyperledger.besu.nativelib.secp256k1;

import org.apache.tuweni.bytes.Bytes;
import org.assertj.core.api.Assertions;
import org.junit.Assume;
import org.junit.Test;

import java.util.Arrays;
import java.util.List;

public class LibSecp256k1JNITest {

  private static final byte[] PUBLIC_KEY =
      Bytes.fromHexString(
              "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                  + "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8")
          .toArrayUnsafe();

  private static final byte[] PRIVATE_KEY =
      Bytes.fromHexString("0000000000000000000000000000000000000000000000000000000000000001")
          .toArrayUnsafe();

  @Test
  public void shouldLoadWhenTheLibraryIsBundledForThisPlatform() {
    // the parameterized tests skip themselves when the library can't be loaded, so a load failure
    // of a library that was built for this platform would otherwise go unnoticed
    String arch = System.getProperty("os.arch");
    if (List.of("amd64", "x86_64", "x64", "ia32e", "EMT64T").contains(arch)) {
      arch = "x86-64";
    }
    String resource =
        String.format("/lib-native/%s/%s", arch, System.mapLibraryName("secp256k1_ecrecover"));
    Assume.assumeNotNull(LibSecp256k1JNITest.class.getResource(resource));

    Assertions.assertThat(LibSecp256k1JNI.ENABLED).as("%s is bundled", resource).isTrue();
  }

  @Test
  public void ecdhShouldClearTheOutputBufferWhenThePublicKeyIsNull() {
    Assume.assumeTrue("secp256k1 native must be enabled", LibSecp256k1JNI.ENABLED);

    byte[] outputBuffer = new byte[33];
    Arrays.fill(outputBuffer, (byte) 0xff);
    Assertions.assertThat(LibSecp256k1JNI.secp256k1_ecdh_jni(null, PRIVATE_KEY, outputBuffer))
        .isEqualTo(1);
    Assertions.assertThat(outputBuffer).containsOnly((byte) 0);
  }

  @Test
  public void ecdhShouldClearTheOutputBufferWhenThePrivateKeyIsNull() {
    Assume.assumeTrue("secp256k1 native must be enabled", LibSecp256k1JNI.ENABLED);

    byte[] outputBuffer = new byte[33];
    Arrays.fill(outputBuffer, (byte) 0xff);
    Assertions.assertThat(LibSecp256k1JNI.secp256k1_ecdh_jni(PUBLIC_KEY, null, outputBuffer))
        .isEqualTo(1);
    Assertions.assertThat(outputBuffer).containsOnly((byte) 0);
  }
}
