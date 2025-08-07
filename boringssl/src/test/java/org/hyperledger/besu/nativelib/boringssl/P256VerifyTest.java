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
package org.hyperledger.besu.nativelib.boringssl;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt256;
import org.junit.Before;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;

public class P256VerifyTest {

  final private Bytes data = Bytes.fromHexString(
      "c35e2f092553c55772926bdbe87c9796827d17024dbb9233a545366e2e5987dd344deb72df987144b8c6c43bc41b654b94cc856e16b96d7a821c8ec039b503e3d86728c494a967d83011a0e090b5d54cd47f4e366c0912bc808fbb2ea96efac88fb3ebec9342738e225f7c7c2b011ce375b56621a20642b4d36e060db4524af1");
  // implied, but not used:
  // final private Bytes privateKey = Bytes.fromHexString("0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813");
  final private Bytes publicKey = Bytes.fromHexString(
      "e266ddfdc12668db30d4ca3e8f7749432c416044f2d2b8c10bf3d4012aeffa8abfa86404a2e9ffe67d47c587ef7a97a7f456b863b4d02cfc6928973ab5b1cb39");
  final private Bytes invalidPublicKey = Bytes.fromHexString(
      "f266ddfdc12668db30d4ca3e8f7749432c416044f2d2b8c10bf3d4012aeffa8abfa86404a2e9ffe67d47c587ef7a97a7f456b863b4d02cfc6928973ab5b1cb39");
  final private Bytes signatureR =
      Bytes.fromHexString("976d3a4e9d23326dc0baa9fa560b7c4e53f42864f508483a6473b6a11079b2db");
  final private Bytes invalidSignatureR =
      Bytes.fromHexString("a76d3a4e9d23326dc0baa9fa560b7c4e53f42864f508483a6473b6a11079b2db");
  final private Bytes signatureS =
      Bytes.fromHexString("1b766e9ceb71ba6c01dcd46e0af462cd4cfa652ae5017d4555b8eeefe36e1932");

  private byte[] dataHash;

  @Before
  public void setUp() throws NoSuchAlgorithmException {
    MessageDigest digest = MessageDigest.getInstance("SHA-256");
    dataHash = digest.digest(data.toArrayUnsafe());
  }

  @Test
  public void verifyValidSignatureSucceeds() {
    byte[] input = createInput(dataHash, signatureR.toArrayUnsafe(), signatureS.toArrayUnsafe(), publicKey.toArrayUnsafe());
    var res = BoringSSLPrecompiles.p256Verify(input, input.length);

    assertThat(res.status).isEqualTo(0);
  }

  @Test
  public void verifyMalleatedSignatureSucceeds() {
    var order =
        UInt256.fromHexString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
    var malleatedSignatureS = order.subtract(UInt256.fromBytes(signatureS));

    byte[] input = createInput(dataHash, signatureR.toArrayUnsafe(), malleatedSignatureS.toArrayUnsafe(), publicKey.toArrayUnsafe());
    var res = BoringSSLPrecompiles.p256Verify(input, input.length);

    assertThat(res.status).isEqualTo(0);
  }

  @Test
  public void verifyShouldReturnErrorIfSignatureIsInvalid() {
    byte[] input = createInput(dataHash, invalidSignatureR.toArrayUnsafe(), signatureS.toArrayUnsafe(), publicKey.toArrayUnsafe());
    var res = BoringSSLPrecompiles.p256Verify(input, input.length);

    assertThat(res.status).isEqualTo(1);
  }

  @Test
  public void verifyShouldThrowExceptionIfAnyOtherParameterIsInvalid() {
    byte[] input = createInput(dataHash, signatureR.toArrayUnsafe(), signatureS.toArrayUnsafe(), invalidPublicKey.toArrayUnsafe());
    var res = BoringSSLPrecompiles.p256Verify(input, input.length);

    assertThat(res.status).isEqualTo(1);
    assertThat(res.error).isEqualTo("failed to parse public key point");
  }

  // Helper method to create 160-byte input array: hash(32) + r(32) + s(32) + pubkey(64)
  private byte[] createInput(byte[] hash, byte[] r, byte[] s, byte[] pubkey) {
    if (hash.length != 32 || r.length != 32 || s.length != 32 || pubkey.length != 64) {
      throw new IllegalArgumentException("Invalid component lengths for input creation");
    }
    
    byte[] input = new byte[160];
    System.arraycopy(hash, 0, input, 0, 32);
    System.arraycopy(r, 0, input, 32, 32);
    System.arraycopy(s, 0, input, 64, 32);
    System.arraycopy(pubkey, 0, input, 96, 64);
    return input;
  }

}
