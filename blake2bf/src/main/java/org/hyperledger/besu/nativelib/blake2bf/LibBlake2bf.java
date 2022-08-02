/*
 * Copyright Hyperledger Besu Contributors.
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
package org.hyperledger.besu.nativelib.blake2bf;

import static java.util.Arrays.copyOfRange;

import com.sun.jna.Library;
import com.sun.jna.Native;
import com.sun.jna.ptr.IntByReference;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.Pack;

public class LibBlake2bf implements Library {
  @SuppressWarnings("WeakerAccess")
  public static final boolean ENABLED;
  public static final int MESSAGE_LENGTH_BYTES = 213;

    private final byte[] buffer;

    private int bufferPos;

    private long rounds; // unsigned integer represented as long


  static {
    boolean enabled;
    try {
      Native.register(LibBlake2bf.class, "blake2bf");
      enabled = true;
    } catch (final Throwable t) {
      enabled = false;
    }
    ENABLED = enabled;
  }

    LibBlake2bf() {
      buffer = new byte[MESSAGE_LENGTH_BYTES];
      bufferPos = 0;
      rounds = 12;

    }

    public static native void blake2bf_eip152(byte[] out, /*long rounds,*/ byte[] payload);
}
