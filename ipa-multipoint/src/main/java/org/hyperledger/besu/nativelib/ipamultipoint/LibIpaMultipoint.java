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
import java.nio.file.Path;
import java.nio.file.Paths;

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
    System.setProperty("jna.prefix", "darwin-aarch64");
    boolean enabled;
    try {
      File lib = Native.extractFromResourcePath("libipa_multipoint_jni");
      System.load(lib.getAbsolutePath());
      enabled = true;
    } catch (IOException e) {
      enabled = false;
    }
    ENABLED = enabled;
  }

  /**
   * Evaluates a polynomial of degree 3 (uniquely defined by 4 values) at a specific point on the curve.

   * @param y0 the first coordinate of the projection on the curve
   * @param y1 the second coordinate of the projection on the curve
   * @param y2 the third coordinate of the projection on the curve
   * @param y3 the fourth coordinate of the projection on the curve
   * @return the coordinates of the projection of the polynomial on the curve
   */
  public static native byte[] commit(byte[] y0, byte[] y1, byte[] y2, byte[] y3);
}
