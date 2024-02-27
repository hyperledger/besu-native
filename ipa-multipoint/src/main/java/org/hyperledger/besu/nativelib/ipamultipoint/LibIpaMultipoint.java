/*
 * Copyright Besu Contributors
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
package org.hyperledger.besu.nativelib.ipamultipoint;

import com.sun.jna.Native;

import java.io.File;
import java.io.IOException;

/**
 * Java interface to ipa-multipoint, a rust library that supports computing polynomial commitments.
 *
 * The library relies on the bandersnatch curve described at https://eprint.iacr.org/2021/1152.pdf.
 *
 */
public class LibIpaMultipoint {

  @SuppressWarnings("WeakerAccess")
  public static final boolean ENABLED;

  static {
    boolean enabled;
    try {
      File lib = Native.extractFromResourcePath("ipa_multipoint_jni");
      System.load(lib.getAbsolutePath());
      enabled = true;
    } catch (IOException e) {
      enabled = false;
    }
    ENABLED = enabled;
  }

  /**
   * Commit to a vector of values.
   *
   * @param byte_size byte size of serialised scalars, at most 32.
   * @param input vector of `byte_size` bytes serialised scalars.
   * @return uncompressed serialised commitment.
   */
  public static native byte[] commit(byte[] input);

  /**
   * Commit to a vector of values.
   *
   * @param byte_size byte size of serialised scalars, at most 32.
   * @param input vector of `byte_size` bytes serialised scalars.
   * @return compressed serialised commitment.
   */
  public static native byte[] commitAsCompressed(byte[] input);

  /**
   * Compresses a commitment.
   *
   * Converts a serialised commitment from uncompressed to compressed form.
   *
   * @param input uncompressed serialised commitment.
   * @return compressed serialised commitment.
   */
  public static native byte[] updateSparse(byte[] commitment, byte[] input);

  /**
   * Compresses a commitment.
   *
   * Converts a serialised commitment from uncompressed to compressed form.
   *
   * @param input uncompressed serialised commitment.
   * @return compressed serialised commitment.
   */
  public static native byte[] toCompressed(byte[] input);

  /**
   * Map a vector of commitments to its corresponding vector of scalars.
   *
   * The vectorised version is highly optimised, making use of Montgoméry's batch
   * inversion trick.
   *
   * @param input vector of uncompressed serialised commitments
   * @return vector of serialised scalars
   */
  public static native byte[] toScalars(byte[] input);
}
