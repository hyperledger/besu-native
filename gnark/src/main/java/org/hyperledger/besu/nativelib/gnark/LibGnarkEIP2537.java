/*
 * Copyright contributors to Besu.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */
package org.hyperledger.besu.nativelib.gnark;

import com.sun.jna.Library;
import com.sun.jna.ptr.IntByReference;
import org.hyperledger.besu.nativelib.common.BesuNativeLibraryLoader;

public class LibGnarkEIP2537 implements Library {

  @SuppressWarnings("WeakerAccess")
  public static final boolean ENABLED;

  // zero implies 'default' degree of parallelism, which is the number of cpu cores available
  private static int degreeOfMSMParallelism = 0;

  static {
    boolean enabled;
    try {
      BesuNativeLibraryLoader.registerJNA(LibGnarkEIP2537.class, "gnark_eip_2537");
      enabled = true;
    } catch (final Throwable t) {
      t.printStackTrace();
      enabled = false;
    }
    ENABLED = enabled;
  }

  public static final int EIP2537_PREALLOCATE_FOR_RESULT_BYTES = 256;
  public static final int EIP2537_PREALLOCATE_FOR_ERROR_BYTES = 256;

  public static final byte BLS12_G1ADD_OPERATION_SHIM_VALUE = 1;
  public static final byte BLS12_G1MULTIEXP_OPERATION_SHIM_VALUE = 2;
  public static final byte BLS12_G2ADD_OPERATION_SHIM_VALUE = 3;
  public static final byte BLS12_G2MULTIEXP_OPERATION_SHIM_VALUE = 4;
  public static final byte BLS12_PAIR_OPERATION_SHIM_VALUE = 5;
  public static final byte BLS12_MAP_FP_TO_G1_OPERATION_SHIM_VALUE = 6;
  public static final byte BLS12_MAP_FP2_TO_G2_OPERATION_SHIM_VALUE = 7;

  /**
   * Here as a compatibility shim for the pre-existing matter-labs implementation.
   *
   * IMPORTANT: The output buffer MUST be zero-initialized before calling this method.
   * The native implementation relies on this pre-initialization for proper functioning.
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
        ret = eip2537blsG1Add(i, output, err, i_len,
            EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
            EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        o_len.setValue(128);
        break;
      case BLS12_G1MULTIEXP_OPERATION_SHIM_VALUE:
       ret = eip2537blsG1MultiExp(i, output, err, i_len,
          EIP2537_PREALLOCATE_FOR_RESULT_BYTES, EIP2537_PREALLOCATE_FOR_ERROR_BYTES,
          degreeOfMSMParallelism);
        o_len.setValue(128);
        break;
      case BLS12_G2ADD_OPERATION_SHIM_VALUE:
        ret = eip2537blsG2Add(i, output, err, i_len,
            EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
            EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        o_len.setValue(256);
        break;
      case BLS12_G2MULTIEXP_OPERATION_SHIM_VALUE:
        ret = eip2537blsG2MultiExp(i, output, err, i_len,
          EIP2537_PREALLOCATE_FOR_RESULT_BYTES, EIP2537_PREALLOCATE_FOR_ERROR_BYTES,
          degreeOfMSMParallelism);
        o_len.setValue(256);
        break;
      case BLS12_PAIR_OPERATION_SHIM_VALUE:
        ret = eip2537blsPairing(i, output, err, i_len,
            EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
            EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        o_len.setValue(32);
        break;
      case BLS12_MAP_FP_TO_G1_OPERATION_SHIM_VALUE:
        ret = eip2537blsMapFpToG1(i, output, err, i_len,
            EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
            EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        o_len.setValue(128);
        break;
      case BLS12_MAP_FP2_TO_G2_OPERATION_SHIM_VALUE:
        ret = eip2537blsMapFp2ToG2(i, output, err, i_len,
            EIP2537_PREALLOCATE_FOR_RESULT_BYTES,
            EIP2537_PREALLOCATE_FOR_ERROR_BYTES);
        o_len.setValue(256);
        break;
      default:
        throw new RuntimeException("Not Implemented EIP-2537 operation " + op);
    }

    if (ret != 0) {
      err_len.setValue(LibGnarkUtils.findFirstTrailingZeroIndex(err));
      o_len.setValue(0);
    } else {
      err_len.setValue(0);
    }
    return ret;
  }


  public static native int eip2537blsG1Add(
      byte[] input,
      byte[] output,
      byte[] error,
      int inputSize, int output_len, int err_len);
  public static native int eip2537blsG1MultiExp(
      byte[] input,
      byte[] output,
      byte[] error,
      int inputSize, int output_len, int err_len,
      int nbTasks);

  public static native int eip2537blsG2Add(
      byte[] input,
      byte[] output,
      byte[] error,
      int inputSize, int output_len, int err_len);
  public static native int eip2537blsG2MultiExp(
      byte[] input,
      byte[] output,
      byte[] error,
      int inputSize, int output_len, int err_len,
      int nbTasks);

  public static native int eip2537blsPairing(
      byte[] input,
      byte[] output,
      byte[] error,
      int inputSize, int output_len, int err_len);

  public static native int eip2537blsMapFpToG1(
      byte[] input,
      byte[] output,
      byte[] error,
      int inputSize, int output_len, int err_len);

  public static native int eip2537blsMapFp2ToG2(
      byte[] input,
      byte[] output,
      byte[] error,
      int inputSize, int output_len, int err_len);

  public static native boolean eip2537G1IsOnCurve(
    byte[] input,
    byte[] error,
    int inputSize, int err_len);

  public static native boolean eip2537G2IsOnCurve(
    byte[] input,
    byte[] error,
    int inputSize, int err_len);

  public static native boolean eip2537G1IsInSubGroup(
    byte[] input,
    byte[] error,
    int inputSize, int err_len);

  public static native boolean eip2537G2IsInSubGroup(
    byte[] input,
    byte[] error,
    int inputSize, int err_len);

  public static void setDegreeOfMSMParallelism(int nbTasks) {
    degreeOfMSMParallelism = nbTasks;
  }
}
