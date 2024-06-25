package org.hyperledger.besu.nativelib.gnark;

import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;
import org.apache.tuweni.bytes.Bytes;

public class LibGnarkEIP196 {

  public static final int EIP196_PREALLOCATE_FOR_RESULT_BYTES = 256; // includes error string
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
        ret = eip196altbn128G1Add(i, output, i_len, EIP196_PREALLOCATE_FOR_RESULT_BYTES);
        o_len.setValue(64);
        break;
      case  EIP196_MUL_OPERATION_RAW_VALUE:
        ret = eip196altbn128G1Mul(i, output, i_len, EIP196_PREALLOCATE_FOR_RESULT_BYTES);
        o_len.setValue(64);
        break;
      case EIP196_PAIR_OPERATION_RAW_VALUE:
        ret = eip196altbn128Pairing(i, output, i_len, EIP196_PREALLOCATE_FOR_RESULT_BYTES);
        o_len.setValue(32);
        break;
      default:
        throw new RuntimeException("Not Implemented EIP-196 operation " + op);
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


  public static native int eip196altbn128G1Add(
      byte[] input,
      byte[] output,
      int inputSize, int outputSize);

  public static native int eip196altbn128G1Mul(
      byte[] input,
      byte[] output,
      int inputSize, int outputSize);

  public static native int eip196altbn128Pairing(
      byte[] input,
      byte[] output,
      int inputSize, int outputSize);
}
