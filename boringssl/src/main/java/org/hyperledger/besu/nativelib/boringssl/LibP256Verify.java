package org.hyperledger.besu.nativelib.boringssl;

import org.hyperledger.besu.nativelib.common.BesuNativeLibraryLoader;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class LibP256Verify {

  public static final boolean ENABLED;

  static {
    boolean enabled;
    try {
      BesuNativeLibraryLoader.registerJNA(LibP256Verify.class, "p256verify");
      enabled = true;
    } catch (final Throwable t) {
      t.printStackTrace();
      enabled = false;
    }
    ENABLED = enabled;
  }

  // Native method
  static native int p256_verify(byte[] data_hash, int data_hash_length, byte[] signature_r,
      byte[] signature_s, byte[] public_key_data, byte[] error_message_buf,
      int error_message_buf_len);

  // Wrapper result class
  public static class Result {
    public final int status;
    public final String message;

    public Result(int status, String message) {
      this.status = status;
      this.message = message;
    }
  }

  // Safe, wrapped version of the native call
  final static int ERROR_BUF_SIZE = 256;

  public static Result p256Verify(byte[] input, int inputLength) {

    byte[] errorBuf = new byte[ERROR_BUF_SIZE];

    if (inputLength != 160) {
      return new Result(2, "incorrect input size");
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

    int nullTerminator = 0;
    while (nullTerminator < errorBuf.length && errorBuf[nullTerminator] != 0) {
      nullTerminator++;
    }

    String message = new String(errorBuf, 0, nullTerminator, StandardCharsets.UTF_8);
    return new Result(status, message);
  }
}
