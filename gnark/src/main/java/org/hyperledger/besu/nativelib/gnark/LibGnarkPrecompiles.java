package org.hyperledger.besu.nativelib.gnark;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;

public class LibGnarkPrecompiles implements Library {

    @SuppressWarnings("WeakerAccess")
    public static final boolean ENABLED;

    static {
      boolean enabled;
      try {
        Native.register(LibGnarkPrecompiles.class, "eth_gnark_precompiles");
        enabled = true;
      } catch (final Throwable t) {
        enabled = false;
      }
      ENABLED = enabled;
    }

    public static final int EIP2537_PREALLOCATE_FOR_ERROR_BYTES = 256;

    public static final int EIP2537_PREALLOCATE_FOR_RESULT_BYTES = 256;

    public static final byte BLS12_G1ADD_OPERATION_RAW_VALUE = 1;
    public static final byte BLS12_G1MUL_OPERATION_RAW_VALUE = 2;
    public static final byte BLS12_G1MULTIEXP_OPERATION_RAW_VALUE = 3;
    public static final byte BLS12_G2ADD_OPERATION_RAW_VALUE = 4;
    public static final byte BLS12_G2MUL_OPERATION_RAW_VALUE = 5;
    public static final byte BLS12_G2MULTIEXP_OPERATION_RAW_VALUE = 6;
    public static final byte BLS12_PAIR_OPERATION_RAW_VALUE = 7;
    public static final byte BLS12_MAP_FP_TO_G1_OPERATION_RAW_VALUE = 8;
    public static final byte BLS12_MAP_FP2_TO_G2_OPERATION_RAW_VALUE = 9;

    public static native int eip2537_perform_operation(
        byte op,
        byte[] i,
        int i_len,
        byte[] o,
        IntByReference o_len,
        byte[] err,
        IntByReference err_len);

}
