/*
 * Copyright ConsenSys AG.
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
package org.hyperledger.besu.nativelib.bls12_381;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;

public class LibEthPairings implements Library {
  @SuppressWarnings("WeakerAccess")
  public static final boolean ENABLED;

  static {
    boolean enabled;
    try {
      Native.register(LibEthPairings.class, "eth_pairings");
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

  public static final int EIP196_PREALLOCATE_FOR_ERROR_BYTES = 256;

  public static final int EIP196_PREALLOCATE_FOR_RESULT_BYTES = 64;

  public static final byte EIP196_ADD_OPERATION_RAW_VALUE = 1;
  public static final byte EIP196_MUL_OPERATION_RAW_VALUE = 2;
  public static final byte EIP196_PAIR_OPERATION_RAW_VALUE = 3;

  public static native int eip196_perform_operation(
      byte op,
      byte[] i,
      int i_len,
      byte[] o,
      IntByReference o_len,
      byte[] err,
      IntByReference char_len);
}
