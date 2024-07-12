package org.hyperledger.besu.nativelib.gnark;

public class LibGnarkUtils {

  public static int findFirstTrailingZeroIndex(byte[] array) {
    for (int i = array.length - 1; i >= 0; i--) {
      if (array[i] != 0) {
        return i + 1; // The first trailing zero is after this non-zero byte
      }
    }
    // If all bytes are zero, return 0
    return 0;
  }
}
