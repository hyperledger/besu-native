/*
 * Copyright Hyperledger Besu contributors.
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
package org.hyperledger.besu.nativelib.altbn128;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;

public class LibAltbn128 implements Library {
  public static final boolean ENABLED;

  static {
    boolean enabled;
    try {
      Native.register(LibAltbn128.class, "eth_altbn128");
      enabled = true;
    } catch (final Throwable t) {
      enabled = false;
    }
    ENABLED = enabled;
  }

  public static native int altbn128_add_precompiled(
      byte[] i, int i_len, byte[] o, IntByReference o_len);

  public static native int altbn128_mul_precompiled(
      byte[] i, int i_len, byte[] o, IntByReference o_len);

  public static native int altbn128_pairing_precompiled(
      byte[] i, int i_len, byte[] o, IntByReference o_len);
}
