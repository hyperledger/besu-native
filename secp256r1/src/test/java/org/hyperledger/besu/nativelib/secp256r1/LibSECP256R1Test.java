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

package org.hyperledger.besu.nativelib.secp256r1;

import org.apache.tuweni.bytes.Bytes;
import org.junit.Before;
import org.junit.Test;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;

public class LibSECP256R1Test {
    final private LibSECP256R1 libSecp256r1 = new LibSECP256R1();

    final private Bytes data = Bytes.fromHexString("5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5473e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8");
    final private Bytes privateKey = Bytes.fromHexString("519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464");
    final private Bytes publicKey = Bytes.fromHexString("1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9");
    final private Bytes invalidPublicKey = Bytes.fromHexString("2ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9");
    final private Bytes signatureR = Bytes.fromHexString("f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac");
    final private Bytes invalidSignatureR = Bytes.fromHexString("e3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac");
    final private Bytes signatureS = Bytes.fromHexString("8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903");
    final int signatureV = 0;

    private byte[] dataHash;

    @Before
    public void setUp() throws NoSuchAlgorithmException {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        dataHash = digest.digest(data.toArrayUnsafe());
    }

    @Test
    public void verify_should_return_true_if_signature_is_valid() {
        boolean verified = libSecp256r1.verify(
                dataHash,
                signatureR.toArrayUnsafe(),
                signatureS.toArrayUnsafe(),
                publicKey.toArrayUnsafe()
        );


        assertThat(verified).isTrue();
    }

    @Test
    public void verify_should_return_false_if_signature_is_invalid() {
        boolean verified = libSecp256r1.verify(
                dataHash,
                invalidSignatureR.toArrayUnsafe(),
                signatureS.toArrayUnsafe(),
                publicKey.toArrayUnsafe()
        );


        assertThat(verified).isFalse();
    }

    @Test(expected = IllegalArgumentException.class)
    public void verify_should_throw_exception_if_any_other_parameter_is_invalid() {
        libSecp256r1.verify(
                dataHash,
                signatureR.toArrayUnsafe(),
                signatureS.toArrayUnsafe(),
                invalidPublicKey.toArrayUnsafe()
        );
    }

    @Test
    public void keyRecovery_should_return_expected_public_key() {
        byte[] actualPublicKey = libSecp256r1.keyRecovery(
            dataHash,
            signatureR.toArrayUnsafe(),
            signatureS.toArrayUnsafe(),
            signatureV
        );

        assertThat(actualPublicKey).isEqualTo(publicKey.toArrayUnsafe());

    }

    @Test(expected = IllegalArgumentException.class)
    public void keyRecovery_should_throw_exception_if_parameter_is_invalid() {
        libSecp256r1.keyRecovery(
                dataHash,
                signatureR.toArrayUnsafe(),
                signatureS.toArrayUnsafe(),
                2
        );
    }

    @Test
    public void sign_should_return_the_expected_signature() {
        Signature signature = libSecp256r1.sign(
                dataHash,
                privateKey.toArrayUnsafe(),
                publicKey.toArrayUnsafe()
        );

        boolean verificationResult = libSecp256r1.verify(
                dataHash,
                signature.getR(),
                signature.getS(),
                publicKey.toArrayUnsafe()
        );

        assertThat(verificationResult).isTrue();

        byte[] recoveredPublicKey = libSecp256r1.keyRecovery(
                dataHash,
                signature.getR(),
                signature.getS(),
                signature.getV()
        );

        assertThat(recoveredPublicKey).isEqualTo(publicKey.toArrayUnsafe());
    }

    @Test(expected = IllegalArgumentException.class)
    public void sign_should_throw_exception_if_parameter_is_invalid() {
        libSecp256r1.sign(
                dataHash,
                privateKey.toArrayUnsafe(),
                invalidPublicKey.toArrayUnsafe()
        );
    }
}