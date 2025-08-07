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

import org.hyperledger.besu.nativelib.common.BesuNativeLibraryLoader;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Optional;

public class BoringSSLPrecompiles {

  public static final boolean ENABLED;

  public static final int STATUS_SUCCESS = 0;
  public static final int STATUS_FAIL = 1;
  public static final int STATUS_ERROR = 2;


  static {
    boolean enabled;
    try {
      BesuNativeLibraryLoader.registerJNA(BoringSSLPrecompiles.class, "boringssl_precompiles");
      enabled = true;
    } catch (final Throwable t) {
      t.printStackTrace();
      enabled = false;
    }
    ENABLED = enabled;
  }

  // Native r1 p256 verify method
  static native int p256_verify(
      final byte[] data_hash, final int data_hash_length,
      final byte[] signature_r, final int signature_r_length,
      final byte[] signature_s, final int signature_s_length,
      final byte[] public_key_data, final int public_key_data_length,
      final byte[] error_message_buf, final int error_message_buf_len);


  // Native r1 ecrecover
  static native int ecrecover_r1(
      final byte[] hash, final int hash_length,
      final byte[] sig, final int sig_length,
      final int recovery_id,
      final byte[] output, final int output_length,
      final byte[] error_message_buf, final int error_message_buf_len);



  // Wrapper result classes
  public static class P256VerifyResult {
    public final int status;
    public final String error;

    public P256VerifyResult(final int status, final String message) {
      this.status = status;
      this.error = message;
    }
  }


  public record ECRecoverResult(
      int status,
      Optional<byte[]> publicKey,
      Optional<String> error) {}


  // Safe, wrapped version of the native calls
  final static int ERROR_BUF_SIZE = 256;

  public static P256VerifyResult p256Verify(final byte[] input, final int inputLength) {

    byte[] errorBuf = new byte[ERROR_BUF_SIZE];

    if (inputLength != 160) {
      return new P256VerifyResult(2, "incorrect input size");
    }

    byte[] dataHash = Arrays.copyOfRange(input, 0, 32);
    byte[] signatureR = Arrays.copyOfRange(input, 32, 64);
    byte[] signatureS = Arrays.copyOfRange(input, 64, 96);
    byte[] uncompressedPubKey = new byte[65];
    // uncompressed point prefix
    uncompressedPubKey[0] = 0x04;
    System.arraycopy(input, 96, uncompressedPubKey, 1, 64);

    int status =
        p256_verify(
            dataHash, dataHash.length,
            signatureR, signatureR.length,
            signatureS, signatureS.length,
            uncompressedPubKey, uncompressedPubKey.length,
            errorBuf, ERROR_BUF_SIZE);

    return new P256VerifyResult(status, bytesToNullTermString(errorBuf));
  }

  // secp256r1 curve order
  private static final BigInteger SECP256R1_ORDER =
      new BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16);

  public static ECRecoverResult ecrecover(final byte[] hash, final byte[] sig,
      final int recovery_id) {
    // Validate signature length
    if (sig == null || sig.length != 64) {
      return new ECRecoverResult(STATUS_ERROR, Optional.empty(),
          Optional.of("invalid signature length"));
    }

    if (hash == null || hash.length != 32) {
      return new ECRecoverResult(STATUS_ERROR, Optional.empty(),
          Optional.of("invalid hash length"));
    }
    byte[] errorBuf = new byte[ERROR_BUF_SIZE];

    // Extract r and s values
    byte[] rBytes = new byte[32];
    byte[] sBytes = new byte[32];
    System.arraycopy(sig, 0, rBytes, 0, 32);
    System.arraycopy(sig, 32, sBytes, 0, 32);

    BigInteger r = new BigInteger(1, rBytes);
    BigInteger s = new BigInteger(1, sBytes);

    // Validate r and s are in range [1, n-1] before calling native method
    if (r.equals(BigInteger.ZERO) || r.compareTo(SECP256R1_ORDER) >= 0) {
      return new ECRecoverResult(STATUS_ERROR, Optional.empty(),
          Optional.of("invalid signature r value"));
    }

    if (s.equals(BigInteger.ZERO) || s.compareTo(SECP256R1_ORDER) >= 0) {
      return new ECRecoverResult(STATUS_ERROR, Optional.empty(),
          Optional.of("invalid signature s value"));
    }

    if (recovery_id < 0 || recovery_id > 1) {
      return new ECRecoverResult(STATUS_ERROR, Optional.empty(),
          Optional.of("invalid recovery id " + recovery_id + " is not 0 or 1"));
    }

    byte[] output = new byte[65];
    byte[] error_buf = new byte[ERROR_BUF_SIZE];
    int status = ecrecover_r1(hash, hash.length, sig, sig.length, recovery_id, output, output.length,
        errorBuf, ERROR_BUF_SIZE);

    if (status == 0) {
      return new ECRecoverResult(status, Optional.of(output), Optional.empty());
    } else {
      String errorMessage = bytesToNullTermString(error_buf);
      return new ECRecoverResult(status, Optional.empty(), Optional.of(errorMessage));
    }
  }

  static String bytesToNullTermString(final byte[] buffer) {
    int nullTerminator = 0;
    while (nullTerminator < buffer.length && buffer[nullTerminator] != 0) {
      nullTerminator++;
    }
    return new String(buffer, 0, nullTerminator, StandardCharsets.UTF_8);
  }

}
