/*
 * Copyright contributors to Hyperledger Besu
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
package org.hyperledger.besu.nativelib.arithmetic;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;

public class LibArithmetic implements Library {

  private LibArithmetic() {}

  public static final boolean ENABLED;

  static {
    boolean enabled;
    try {
      Native.register(LibArithmetic.class, "eth_arithmetic");
      enabled = true;
    } catch (final Exception t) {
      enabled = false;
    }
    ENABLED = enabled;
  }

  public static native int modexp_precompiled(byte[] i, int i_len, byte[] o, IntByReference o_len);
}
