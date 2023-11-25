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
   * Vector commitment(pedersen) expecting up to 256 32bytes values. Returns serialized commitment.
   * @param input [Fr,Fr,Fr...]
   * @return commitment.as_bytes() which is a Fp * sign(y) as 32byte value
   */
  public static native byte[] commit(byte[] input);

  /**
   * Update commitment for 1 commitment, for `diff value` at `index`. Additively homomorphic.
   * Expects commitment serialized as bytes (32bytes - Fp x coordinate * sign(y coordinate)), diff value (32bytes) (Fr), and index (1byte)
   * Returns commitment serialized as bytes(32bytes - Fp x coordinate * sign(y coordinate))
   * @param input Expects 65byte value as input encoded as byte[]
   * @return 32bytes as byte[]
   */
  public static native byte[] updateCommitment(byte[] input);

  /**
   * Pedersen hash as specified in https://notes.ethereum.org/@vbuterin/verkle_tree_eip
   * @param input Expects 64byte value as input encoded as byte[]
   * @return 32bytes as byte[]
   */
  public static native byte[] pedersenHash(byte[] input);

  /**
   * Group to field. Maps serialized Banderwagon Element to Fr.
   * @param input Expects 32byte serialized commitment(banderwagon Element) (32bytes Fp x coordinate * sign(y coordinate)) as input encoded as byte[]
   * @return 32bytes as byte[] - Fr
   */
  public static native byte[] groupToField(byte[] input);
}
