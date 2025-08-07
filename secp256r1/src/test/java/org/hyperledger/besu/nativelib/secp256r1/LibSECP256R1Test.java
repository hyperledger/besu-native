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
package org.hyperledger.besu.nativelib.secp256r1;

import org.apache.tuweni.bytes.Bytes;
import org.apache.tuweni.units.bigints.UInt256;
import org.assertj.core.util.Hexadecimals;
import org.junit.Before;
import org.junit.Test;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

public class LibSECP256R1Test {
    final private LibSECP256R1 libSecp256r1 = new LibSECP256R1();

    final private Bytes data = Bytes.fromHexString("c35e2f092553c55772926bdbe87c9796827d17024dbb9233a545366e2e5987dd344deb72df987144b8c6c43bc41b654b94cc856e16b96d7a821c8ec039b503e3d86728c494a967d83011a0e090b5d54cd47f4e366c0912bc808fbb2ea96efac88fb3ebec9342738e225f7c7c2b011ce375b56621a20642b4d36e060db4524af1");
    final private Bytes privateKey = Bytes.fromHexString("0f56db78ca460b055c500064824bed999a25aaf48ebb519ac201537b85479813");
    final private Bytes publicKey = Bytes.fromHexString("e266ddfdc12668db30d4ca3e8f7749432c416044f2d2b8c10bf3d4012aeffa8abfa86404a2e9ffe67d47c587ef7a97a7f456b863b4d02cfc6928973ab5b1cb39");
    final private Bytes invalidPublicKey = Bytes.fromHexString("f266ddfdc12668db30d4ca3e8f7749432c416044f2d2b8c10bf3d4012aeffa8abfa86404a2e9ffe67d47c587ef7a97a7f456b863b4d02cfc6928973ab5b1cb39");
    final private Bytes signatureR = Bytes.fromHexString("976d3a4e9d23326dc0baa9fa560b7c4e53f42864f508483a6473b6a11079b2db");
    final private Bytes invalidSignatureR = Bytes.fromHexString("a76d3a4e9d23326dc0baa9fa560b7c4e53f42864f508483a6473b6a11079b2db");
    final private Bytes signatureS = Bytes.fromHexString("1b766e9ceb71ba6c01dcd46e0af462cd4cfa652ae5017d4555b8eeefe36e1932");
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
    public void verify_malleated_signature() {
        var order = UInt256.fromHexString(
            "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
        var malleatedSignatureS = order.subtract(UInt256.fromBytes(signatureS));

        boolean verified = libSecp256r1.verify(
            dataHash,
            signatureR.toArrayUnsafe(),
            malleatedSignatureS.toArrayUnsafe(),
            publicKey.toArrayUnsafe(),
            true
        );

        assertThat(verified).isTrue();

        // assert that canonical verification fails:
        assertThatThrownBy(() ->
            libSecp256r1.verify(
                dataHash,
                signatureR.toArrayUnsafe(),
                malleatedSignatureS.toArrayUnsafe(),
                publicKey.toArrayUnsafe(),
                false
            )
        ).isInstanceOf(IllegalArgumentException.class)
            .hasMessage("Signature is not canonicalized. s of signature must not be greater than n / 2: : error:00000000:lib(0)::reason(0)");
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

    @Test
    public void keyRecovery_should_return_expected_public_key_if_r_is_less_than_32_bytes_long() {
        final BigInteger r = new BigInteger("607232317131644998607993399928086035368869502933999419429470745918733484");
        final BigInteger s = new BigInteger("909326537358980219114547956988636184748037502936154044628658501523731230682");
        final byte v = (byte) 1;
        final Bytes dataHash = Bytes.fromHexString("0x5d2a686cbe81873192db62f069cc1f0c10a1580c89d19c21407dcd1cde48ad06");


        byte[] actualPublicKey = libSecp256r1.keyRecovery(
                dataHash.toArrayUnsafe(),
                r.toByteArray(),
                s.toByteArray(),
                v
        );

        assertThat(Hexadecimals.toHexString(actualPublicKey)).isEqualTo("33F004F357282E13036385D3F52A90F5E62FA0D51C39DFF99CB72FD06CB5FAB72F2DC5E05786154DD7A349DC3FDD9BE2F0B9665C4E08FA6CDC1FD447112ACF3F");
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
