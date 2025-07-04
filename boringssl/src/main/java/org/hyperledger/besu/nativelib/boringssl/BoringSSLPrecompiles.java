package org.hyperledger.besu.nativelib.boringssl;

import org.hyperledger.besu.nativelib.common.BesuNativeLibraryLoader;

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
  static native int p256_verify(final byte[] data_hash, final int data_hash_length, final byte[] signature_r,
      final byte[] signature_s, final byte[] public_key_data, final byte[] error_message_buf,
      final int error_message_buf_len);


  // Native r1 ecrecover
  static native int ecrecover_r1(final byte[] hash, final byte[] sig, final int recovery_id, final byte[] output);



  // Wrapper result classes
  public static class P256VerifyResult {
    public final int status;
    public final String error;

    public P256VerifyResult(final int status, final String message) {
      this.status = status;
      this.error = message;
    }
  }

  public static class EcrecoverResult {
    public final int status;
    public final Optional<byte[]> publicKey;
    public final Optional<String> error;

    public EcrecoverResult(final int status, final Optional<byte[]> publicKey, final Optional<String> error) {
      this.status = status;
      this.publicKey = publicKey;
      this.error = error;
    }
  }

  // Safe, wrapped version of the native calls
  final static int ERROR_BUF_SIZE = 256;

  public static P256VerifyResult p256Verify(final byte[] input, final int inputLength) {

    byte[] errorBuf = new byte[ERROR_BUF_SIZE];

    if (inputLength != 160) {
      return new P256VerifyResult(2, "incorrect input size");
    }

    byte[] dataHash  = Arrays.copyOfRange(input, 0,   32);
    byte[] signatureR  = Arrays.copyOfRange(input, 32,  64);
    byte[] signatureS  = Arrays.copyOfRange(input, 64,  96);
    byte[] uncompressedPubKey = new byte[65];
    // uncompressed point prefix
    uncompressedPubKey[0] = 0x04;
    System.arraycopy(input, 96, uncompressedPubKey, 1, 64);

    int status = p256_verify(
        dataHash,
        dataHash.length,
        signatureR,
        signatureS,
        uncompressedPubKey,
        errorBuf,
        ERROR_BUF_SIZE);

    return new P256VerifyResult(status, bytesToNullTermString(errorBuf));
  }

  public static EcrecoverResult ecrecover(final byte[] hash, final byte[] sig, final int recovery_id) {
    byte[] output = new byte[ERROR_BUF_SIZE];
    int status = ecrecover_r1(hash, sig, recovery_id, output);

    if (status == 0) {
      byte[] publicKey = new byte[65];
      System.arraycopy(output, 0, publicKey, 0, 65);
      return new EcrecoverResult(status, Optional.of(publicKey), Optional.empty());
    } else {
      return new EcrecoverResult(status, Optional.empty(),
          Optional.of("ecrecover failed"));
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
