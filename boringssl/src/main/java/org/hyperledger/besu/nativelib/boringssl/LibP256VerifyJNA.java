package org.hyperledger.besu.nativelib.boringssl;

import com.sun.jna.Structure;
import org.hyperledger.besu.nativelib.common.BesuNativeLibraryLoader;

public class LibP256VerifyJNA {

  public static final boolean ENABLED;

  static {
    boolean enabled;
    try {
      BesuNativeLibraryLoader.registerJNA(LibP256VerifyJNA.class, "p256verify");
      enabled = true;
    } catch (final Throwable t) {
      t.printStackTrace();
      enabled = false;
    }
    ENABLED = enabled;
  }

  /**
   * Original signature : <code>verify_result p256_verify_jna(const char[], const int, const char[], const char[], const char[])</code><br>
   */
  public static native VerifyResultByValue p256_verify_jna(byte[] data_hash, int data_hash_length, byte[] signature_r, byte[] signature_s, byte[] public_key_data);

  @Structure.FieldOrder({"status", "message"})
  public static class VerifyResultByValue extends Structure implements Structure.ByValue {
    public int status;            // 0 = OK, 1 = INVALID, 2 = ERROR
    public String message;        // optional diagnostic string
    
    public VerifyResultByValue() {
      super();
    }
    
    public VerifyResultByValue(int status, String message) {
      this.status = status;
      this.message = message;
    }
  }

  // Wrapper result class for consistency with JNI version
  public static class Result {
    public final int status;
    public final String message;

    public Result(int status, String message) {
      this.status = status;
      this.message = message;
    }
  }

  // Safe, wrapped version of the native call
  public static Result p256Verify(byte[] dataHash, byte[] signatureR, byte[] signatureS,
      byte[] publicKey) {

    VerifyResultByValue result = p256_verify_jna(dataHash, dataHash.length, signatureR, signatureS, publicKey);
    
    return new Result(result.status, result.message != null ? result.message : "");
  }

  /**
   * BoringSSL wants a 0x04 type prefix. Upstream Besu should prefix keys since
   * EIP-7951 only specifies 64 byte public key.
   */
  public static byte[] prefixPublicKey(byte[] pubKeyBytes) {
    byte[] prefixed = new byte[1 + pubKeyBytes.length];
    prefixed[0] = 0x04;
    System.arraycopy(pubKeyBytes, 0, prefixed, 1, pubKeyBytes.length);
    return prefixed;
  }
}