package org.hyperledger.besu.nativelib.gnark;

import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;

public class LibGnarkEIP196 {

  public static final int EIP196_PREALLOCATE_FOR_RESULT_BYTES = 128;
  public static final int EIP196_PREALLOCATE_FOR_ERROR_BYTES = 256; // includes error string
  @SuppressWarnings("WeakerAccess")
  public static final byte EIP196_ADD_OPERATION_RAW_VALUE = 1;
  public static final byte EIP196_MUL_OPERATION_RAW_VALUE = 2;
  public static final byte EIP196_PAIR_OPERATION_RAW_VALUE = 3;

  public static final boolean ENABLED;

  static {
    boolean enabled;
    try {
      Native.register(LibGnarkEIP196.class, "gnark_eip_196");
      enabled = true;
    } catch (final Throwable t) {
      t.printStackTrace();
      enabled = false;
    }
    ENABLED = enabled;
  }

  /**
   * Here as a compatibility shim for the pre-existing matter-labs implementation.
   */
  public static int eip196_perform_operation(
      byte op,
      byte[] i,
      int i_len,
      byte[] output,
      IntByReference o_len,
      byte[] err,
      IntByReference err_len) {

    int ret = -1;
    switch(op) {
      case EIP196_ADD_OPERATION_RAW_VALUE:
        ret = eip196altbn128G1Add(i, output, err, i_len, o_len, err_len);
        break;
      case  EIP196_MUL_OPERATION_RAW_VALUE:
        ret = eip196altbn128G1Mul(i, output, err, i_len, o_len, err_len);
        break;
      case EIP196_PAIR_OPERATION_RAW_VALUE:
        ret = eip196altbn128Pairing(i, output, err, i_len, o_len, err_len);
        break;
      default:
        throw new RuntimeException("Not Implemented EIP-196 operation " + op);
    }

    return ret;
  }

  public static native int eip196altbn128G1Add(
      byte[] input,
      byte[] output,
      byte[] error,
      int inputSize, IntByReference outputSize, IntByReference err_len);

  public static native int eip196altbn128G1Mul(
      byte[] input,
      byte[] output,
      byte[] error,
      int inputSize, IntByReference output_len, IntByReference err_len);

  public static native int eip196altbn128Pairing(
      byte[] input,
      byte[] output,
      byte[] error,
      int inputSize, IntByReference output_len, IntByReference err_len);
}
