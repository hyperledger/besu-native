package org.hyperledger.besu.nativelib.gnark;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;
import org.apache.tuweni.bytes.Bytes;

import java.nio.charset.StandardCharsets;

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

  public static final byte BLS12_G1ADD_OPERATION_SHIM_VALUE = 1;
  public static final byte BLS12_G1MUL_OPERATION_SHIM_VALUE = 2;
  public static final byte BLS12_G1MULTIEXP_OPERATION_SHIM_VALUE = 3;
  public static final byte BLS12_G2ADD_OPERATION_SHIM_VALUE = 4;
  public static final byte BLS12_G2MUL_OPERATION_SHIM_VALUE = 5;
  public static final byte BLS12_G2MULTIEXP_OPERATION_SHIM_VALUE = 6;
  public static final byte BLS12_PAIR_OPERATION_SHIM_VALUE = 7;
  public static final byte BLS12_MAP_FP_TO_G1_OPERATION_SHIM_VALUE = 8;
  public static final byte BLS12_MAP_FP2_TO_G2_OPERATION_SHIM_VALUE = 9;

  /**
   * Here as a compatibility shim for the pre-existing matter-labs implementation.
   */
  public static int eip2537_perform_operation(
      byte op,
      byte[] i,
      int i_len,
      byte[] output,
      IntByReference o_len,
      byte[] err,
      IntByReference err_len) {

    int ret = -1;
    switch(op) {
      case BLS12_G1ADD_OPERATION_SHIM_VALUE:
        ret = eip2537blsG1Add(i, output, i_len, EIP2537_PREALLOCATE_FOR_RESULT_BYTES);
        o_len.setValue(128);
        break;
      case  BLS12_G1MUL_OPERATION_SHIM_VALUE:
        ret = eip2537blsG1Mul(i, output, i_len, EIP2537_PREALLOCATE_FOR_RESULT_BYTES);
        o_len.setValue(128);
        break;
      case BLS12_G1MULTIEXP_OPERATION_SHIM_VALUE:
        ret = eip2537blsG1MultiExp(i, output, i_len, EIP2537_PREALLOCATE_FOR_RESULT_BYTES);
        o_len.setValue(128);
        break;
      case BLS12_G2ADD_OPERATION_SHIM_VALUE:
        ret = eip2537blsG2Add(i, output, i_len, EIP2537_PREALLOCATE_FOR_RESULT_BYTES);
        o_len.setValue(256);
        break;
      case BLS12_G2MUL_OPERATION_SHIM_VALUE:
        ret = eip2537blsG2Mul(i, output, i_len, EIP2537_PREALLOCATE_FOR_RESULT_BYTES);
        o_len.setValue(256);
        break;
      case BLS12_G2MULTIEXP_OPERATION_SHIM_VALUE:
        ret = eip2537blsG2MultiExp(i, output, i_len, EIP2537_PREALLOCATE_FOR_RESULT_BYTES);
        o_len.setValue(256);
        break;
      case BLS12_PAIR_OPERATION_SHIM_VALUE:
        ret = eip2537blsPairing(i, output, i_len, EIP2537_PREALLOCATE_FOR_RESULT_BYTES);
        o_len.setValue(32);
        break;
      case BLS12_MAP_FP_TO_G1_OPERATION_SHIM_VALUE:
        ret = eip2537blsMapFpToG1(i, output, i_len, EIP2537_PREALLOCATE_FOR_RESULT_BYTES);
        o_len.setValue(128);
        break;
      case BLS12_MAP_FP2_TO_G2_OPERATION_SHIM_VALUE:
        ret = eip2537blsMapFp2ToG2(i, output, i_len, EIP2537_PREALLOCATE_FOR_RESULT_BYTES);
        o_len.setValue(256);
        break;
      default:
        throw new RuntimeException("Not Implemented EIP-2537 operation " + op);
    }

    if (ret != 0) {
      var outputBytes = Bytes.wrap(output);
      var outputLen = outputBytes.size() - outputBytes.numberOfTrailingZeroBytes();
      err_len.setValue(outputLen);
      o_len.setValue(0);
      System.arraycopy(output, 0, err, 0, err_len.getValue());
    } else {
      err_len.setValue(0);
    }
    return ret;

  }


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
