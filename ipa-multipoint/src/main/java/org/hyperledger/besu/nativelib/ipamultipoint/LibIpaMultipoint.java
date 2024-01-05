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
   * Evaluates a polynomial of degree 255 (uniquely defined by 256 values) at a specific point on the curve.

   * @param input [Fr,Fr,Fr...]
   * @return group_to_field(commitment)
   */
  public static native byte[] commit(byte[] input);

  /**
   * Evaluates a polynomial of degree 255 (uniquely defined by 256 values) at a specific point on the curve.
   * @param input [Fr,Fr,Fr...]
   * @return commitment.to_bytes()
   */
  public static native byte[] commitRoot(byte[] input);

  /**
   * Pedersen hash as specified in https://notes.ethereum.org/@vbuterin/verkle_tree_eip
   * @param input Expects 64byte value as input encoded as byte[]
   * @return 32bytes as byte[]
   */
  public static native byte[] pedersenHash(byte[] input);
}
