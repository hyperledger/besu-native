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

import com.sun.jna.ptr.IntByReference;
import org.hyperledger.besu.nativelib.common.BesuNativeLibraryLoader;

public class LibGnarkEIP196 {

  public static final int EIP196_PREALLOCATE_FOR_RESULT_BYTES = 64;
  @SuppressWarnings("WeakerAccess")
  public static final byte EIP196_ADD_OPERATION_RAW_VALUE = 1;
  public static final byte EIP196_MUL_OPERATION_RAW_VALUE = 2;
  public static final byte EIP196_PAIR_OPERATION_RAW_VALUE = 3;

  public static final boolean ENABLED;

  // Keep in sync with the Go code. We use constant values to avoid passing strings from Java to Go
  // errCodeSuccess errorCode = iota
  // errCodeMalformedPointEIP196
  // errCodeInvalidInputPairingLengthEIP196
  // errCodePointNotInFieldEIP196
  // errCodePointInSubgroupCheckFailedEIP196
  // errCodePointOnCurveCheckFailedEIP196
  // errCodePairingCheckErrorEIP196
  public static final int EIP196_ERR_CODE_SUCCESS = 0;
  public static final int EIP196_ERR_CODE_MALFORMED_POINT = 1;
  public static final int EIP196_ERR_CODE_INVALID_INPUT_PAIRING_LENGTH = 2;
  public static final int EIP196_ERR_CODE_POINT_NOT_IN_FIELD = 3;
  public static final int EIP196_ERR_CODE_POINT_IN_SUBGROUP_CHECK_FAILED = 4;
  public static final int EIP196_ERR_CODE_POINT_ON_CURVE_CHECK_FAILED = 5;
  public static final int EIP196_ERR_CODE_PAIRING_CHECK_ERROR = 6;


  static {
    boolean enabled;
    try {
      BesuNativeLibraryLoader.registerJNA(LibGnarkEIP196.class, "gnark_eip_196");
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
      byte[] output) {

    int ret = -1;
    switch(op) {
      case EIP196_ADD_OPERATION_RAW_VALUE:
        ret = eip196altbn128G1Add(i, output, i_len);
        break;
      case  EIP196_MUL_OPERATION_RAW_VALUE:
        ret = eip196altbn128G1Mul(i, output, i_len);
        break;
      case EIP196_PAIR_OPERATION_RAW_VALUE:
        ret = eip196altbn128Pairing(i, output, i_len);
        // Result is already written to output buffer by Go
        // ret is only non-zero for actual errors
        break;
      default:
        throw new RuntimeException("Not Implemented EIP-196 operation " + op);
    }

    return ret;
  }

  public static native int eip196altbn128G1Add(
      byte[] input,
      byte[] output,
      int inputSize);

  public static native int eip196altbn128G1Mul(
      byte[] input,
      byte[] output,
      int inputSize);

  public static native int eip196altbn128Pairing(
      byte[] input,
      byte[] output,
      int inputSize);
}
