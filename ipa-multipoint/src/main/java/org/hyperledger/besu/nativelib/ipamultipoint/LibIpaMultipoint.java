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
   * @param values vector of serialised scalars to commit to.
   * @return uncompressed serialised commitment.
   */
  public static native byte[] commit(byte[] values);

  /**
   * Commit to a vector of values and compress commitment.
   *
   * @param values vector of serialised scalars to commit to.
   * @return compressed serialised commitment.
   */
  public static native byte[] commitAsCompressed(byte[] values);

  /**
   * Update a commitment with a sparse vector.
   *
   * @param commitment uncompressed serialised commitment.
   * @param indices indices in value vector to update.
   * @param oldValues old serialised scalars to update.
   * @param newValues new serialised scalars.
   * @return uncompressed serialised commitment.
   */
  public static native byte[] updateSparse(byte[] commitment, byte[] indices, byte[] oldValues, byte[] newValues);

  /**
   * Compresses a commitment.
   *
   * Converts a serialised commitment from uncompressed to compressed form.
   *
   * @param commitment uncompressed serialised commitment.
   * @return compressed serialised commitment.
   */
  public static native byte[] compress(byte[] commitment);

  /**
   * Compresses many commitments.
   *
   * Converts a serialised commitment from uncompressed to compressed form.
   *
   * @param commitments uncompressed serialised commitments.
   * @return compressed serialised commitments.
   */
  public static native byte[] compressMany(byte[] commitments);

  /**
   * Convert a commitment to its corresponding scalar.
   *
   * @param commitment uncompressed serialised commitment
   * @return serialised scalar
   */
  public static native byte[] hash(byte[] commitment);

  /**
   * Map a vector of commitments to its corresponding vector of scalars.
   *
   * The vectorised version is highly optimised, making use of Montgoméry's batch
   * inversion trick.
   *
   * @param commitments uncompressed serialised commitments
   * @return serialised scalars
   */
  public static native byte[] hashMany(byte[] commitments);
}
