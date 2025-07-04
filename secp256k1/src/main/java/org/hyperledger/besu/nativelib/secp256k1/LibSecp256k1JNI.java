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
 */
package org.hyperledger.besu.nativelib.secp256k1;

import com.sun.jna.Native;
import org.hyperledger.besu.nativelib.common.BesuNativeLibraryLoader;

public class LibSecp256k1JNI {

  public static final boolean ENABLED;

  static {
    boolean enabled;
    try {
      BesuNativeLibraryLoader.registerJNA(LibSecp256k1JNI.class, "secp256k1_ecrecover");
      enabled = true;
    } catch (final Throwable t) {
      t.printStackTrace();
      enabled = false;
    }
    ENABLED = enabled;
  }

  /**
   * Consolidated ECRECOVER operation using JNI for optimal performance.
   * 
   * This method combines signature parsing, public key recovery, and serialization
   * into a single native call to minimize JNI overhead.
   * 
   * @param messageHash the 32-byte message hash that was signed
   * @param signature the 64-byte compact signature (r || s)
   * @param recoveryId the recovery ID (0, 1, 2, or 3)
   * @param outputBuffer the output buffer to write the recovered public key (65 bytes uncompressed)
   * @return 1 if recovery was successful, 0 otherwise
   */
  public static native int secp256k1_ecrecover_jni(
      byte[] messageHash,
      byte[] signature,
      int recoveryId,
      byte[] outputBuffer);

  /**
   * Result wrapper for ECRECOVER operations
   */
  public static class ECRecoverResult {
    public final boolean success;
    public final byte[] publicKey; // 64 bytes (without 0x04 prefix)
    
    public ECRecoverResult(boolean success, byte[] publicKey) {
      this.success = success;
      this.publicKey = publicKey;
    }
  }

  /**
   * Safe wrapper for the native ECRECOVER operation.
   * 
   * @param messageHash the 32-byte message hash that was signed
   * @param signature the 64-byte compact signature (r || s)
   * @param recoveryId the recovery ID (0, 1, 2, or 3)
   * @return ECRecoverResult containing success status and recovered public key
   */
  public static ECRecoverResult ecrecover(byte[] messageHash, byte[] signature, int recoveryId) {
    if (messageHash == null || messageHash.length != 32) {
      throw new IllegalArgumentException("messageHash must be 32 bytes");
    }
    if (signature == null || signature.length != 64) {
      throw new IllegalArgumentException("signature must be 64 bytes");
    }
    if (recoveryId < 0 || recoveryId > 3) {
      throw new IllegalArgumentException("recoveryId must be 0, 1, 2, or 3");
    }

    byte[] outputBuffer = new byte[65]; // uncompressed public key format
    int result = secp256k1_ecrecover_jni(messageHash, signature, recoveryId, outputBuffer);
    
    if (result == 1) {
      // Strip the 0x04 prefix to get the 64-byte public key
      byte[] publicKey = new byte[64];
      System.arraycopy(outputBuffer, 1, publicKey, 0, 64);
      return new ECRecoverResult(true, publicKey);
    } else {
      return new ECRecoverResult(false, null);
    }
  }
}
