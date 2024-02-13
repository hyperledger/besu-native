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
   * @return commitment.to_bytes() - uncompressed serialization
   */
  public static native byte[] commit(byte[] input);

  /**
   * Evaluates a polynomial of degree 255 (uniquely defined by 256 values) at a specific point on the curve.
   * @param input [Fr,Fr,Fr...]
   * @return commitment.to_bytes() - compressed serialization
   */
  public static native byte[] commitRoot(byte[] input);

  /**
   * Serializaes group element to field.
   * @param input C uncompressed serialization = 64bytes
   * @return Fr = 32 bytes
   */
  public static native byte[] groupToField(byte[] input);

  /**
   * Pedersen hash as specified in https://notes.ethereum.org/@vbuterin/verkle_tree_eip
   * @param input Expects 64byte value as input encoded as byte[]
   * @return 32bytes as byte[]
   */
  public static native byte[] pedersenHash(byte[] input);

  /**
   * Update Commitment sparse
   * @param input Expects byteArray of fixed 64bytes for the commitment
   * and dynamic tuple (old_scalar(32 bytes), new_scalar(32 bytes), index(1 byte)) in this sequence
   * Bytearray is processed with ffi_interface::deserialize_update_commitment_sparse and sent to ffi_interface::update_commitment_sparse.
   * If Commitment is empty we should pass https://github.com/crate-crypto/rust-verkle/blob/bb5af2f2fe9788d49d2896b9614a3125f8227818/ffi_interface/src/lib.rs#L57
   * @return Updated commitemnt and return it as 64 bytes.
   */
  public static native byte[] updateCommitmentSparse(byte[] input);


  /**
   * Receives a tuple (C_i, f_i(X), z_i, y_i)
   * Where C_i is a commitment to f_i(X) serialized as 32 bytes
   * f_i(X) is the polynomial serialized as 8192 bytes since we have 256 Fr elements each serialized as 32 bytes
   * z_i is index of the point in the polynomial: 1 byte (number from 1 to 256)
   * y_i is the evaluation of the polynomial at z_i i.e. value we are opening: 32 bytes
   * Returns a proof serialized as bytes
   * This function assumes that the domain is always 256 values and commitment is 32bytes.
   * @param input (C_i: 32bytes, f_i(X): 8192bytes, z_i: 1byte, y_i: 32bytes) tuple of 8257bytes for each opening
   * @return proof.as_bytes()
   */
  public static native byte[] createProof(byte[] input);


  /**
   * Receives a proof and a tuple (C_i, z_i, y_i)
   * Where C_i is a commitment to f_i(X) serialized as 64 bytes (uncompressed commitment)
   * z_i is index of the point in the polynomial: 1 byte (number from 1 to 256)
   * y_i is the evaluation of the polynomial at z_i i.e value we are opening: 32 bytes or Fr (scalar field element)
   * Returns true of false.
   * Proof is verified or not.
   * Proof bytes are 576 bytes
   * First 32 bytes is the g_x_comm_bytes
   * Next 544 bytes are part of IPA proof. Domain size is always 256. Explanation is in IPAProof::from_bytes().
   * Next N bytes are (Ci: 32bytes, zi: 1byte, yi: 32bytes) tuples of 65bytes for commitments and values we are verifying.
   * @param input proof.as_bytes()
   * @return boolean
   */
  public static native boolean verifyProof(byte[] input);
}
