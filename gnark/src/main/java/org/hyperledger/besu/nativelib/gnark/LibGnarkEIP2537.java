package org.hyperledger.besu.nativelib.gnark;

import com.sun.jna.Library;
import com.sun.jna.Native;

public class LibGnarkEIP2537 implements Library {

    @SuppressWarnings("WeakerAccess")
    public static final boolean ENABLED;

    static {
      boolean enabled;
      try {
        Native.register(LibGnarkEIP2537.class, "gnark_eip_2537");
        enabled = true;
      } catch (final Throwable t) {
        t.printStackTrace();
        enabled = false;
      }
      ENABLED = enabled;
    }

  public static final int EIP2537_PREALLOCATE_FOR_RESULT_BYTES = 256;

  public static native int eip2537blsG1Add(
      byte[] input,
      byte[] output,
      int inputSize, int outputSize);

  public static native int eip2537blsG1Mul(
      byte[] input,
      byte[] output,
      int inputSize, int outputSize);

  public static native int eip2537blsG1MultiExp(
      byte[] input,
      byte[] output,
      int inputSize, int outputSize);

  public static native int eip2537blsG2Add(
      byte[] input,
      byte[] output,
      int inputSize, int outputSize);

  public static native int eip2537blsG2Mul(
      byte[] input,
      byte[] output,
      int inputSize, int outputSize);

  public static native int eip2537blsG2MultiExp(
      byte[] input,
      byte[] output,
      int inputSize, int outputSize);

  public static native int eip2537blsPairing(
      byte[] input,
      byte[] output,
      int inputSize, int outputSize);

  public static native int eip2537blsMapFpToG1(
      byte[] input,
      byte[] output,
      int inputSize, int outputSize);

  public static native int eip2537blsMapFp2ToG2(
      byte[] input,
      byte[] output,
      int inputSize, int outputSize);

}
