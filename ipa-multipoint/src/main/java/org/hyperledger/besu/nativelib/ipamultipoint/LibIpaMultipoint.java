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
package org.hyperledger.besu.nativelib.ipamultipoint;

import com.sun.jna.Library;
import com.sun.jna.Native;
import org.hyperledger.besu.nativelib.common.BesuNativeLibraryLoader;

import java.io.File;

/**
 * Java interface to ipa-multipoint, a rust library that supports computing polynomial commitments.
 *
 * The library relies on the bandersnatch curve described at https://eprint.iacr.org/2021/1152.pdf.
 *
 */
public class LibIpaMultipoint implements Library {

  @SuppressWarnings("WeakerAccess")
  public static final boolean ENABLED;

  static {
    boolean enabled;
    try {
      BesuNativeLibraryLoader.loadJNI(LibIpaMultipoint.class, "ipa_multipoint_jni");
      enabled = true;
    } catch (Exception e) {
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

  /**
   * Verifies the Verkle proof against the specified pre-state root
   * <p>
   * This method interfaces with a native Rust implementation to verify a Verkle proof
   * against the specified pre-state root.
   * </p>
   *
   * @param keys accessed or modified keys
   * @param currentValues current values associated with the keys.
   * @param commitmentsByPath commitments along the path in the Verkle trie.
   * @param cl left commitments in the IPA proof.
   * @param cr right commitments in the IPA proof.
   * @param otherStems others stems that are present.
   * @param d aggregated commitment to the polynomial D in the IPA proof.
   * @param depthsExtensionPresentStems depths and extension presence for each stem.
   * @param finalEvaluation final evaluation point in the IPA proof.
   * @param prestateRoot root of the prestate to be verified against.
   * @return true if prestate root is correct
   */
  public static native boolean verifyPreStateRoot(byte[][] keys,
                                                  byte[][] currentValues,
                                                  byte[][] commitmentsByPath,
                                                  byte[][] cl,
                                                  byte[][] cr,
                                                  byte[][] otherStems,
                                                  byte[] d,
                                                  byte[] depthsExtensionPresentStems,
                                                  byte[] finalEvaluation,
                                                  byte[] prestateRoot);

}
