package org.hyperledger.besu.nativelib.boringssl;

import com.sun.jna.Structure;
import org.hyperledger.besu.nativelib.common.BesuNativeLibraryLoader;

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

  /**
   * Original signature : <code>verify_result p256_verify(const char[], const int, const char[], const char[], const char[])</code><br>
   */
  public static native VerifyResultByValue p256_verify(byte[] data_hash, int data_hash_length, byte[] signature_r, byte[] signature_s, byte[] public_key_data);


  @Structure.FieldOrder({"status", "message"})
  public static class VerifyResultByValue extends Structure implements Structure.ByValue {
    public int status;            // 0 = OK, 1 = INVALID, 2 = ERROR
    public String message;        // optional diagnostic string
  }

}
