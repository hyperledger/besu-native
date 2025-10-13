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
package org.hyperledger.besu.nativelib.secp256k1;

import org.graalvm.nativeimage.PinnedObject;
import org.graalvm.nativeimage.c.type.CCharPointer;

/**
 * Helper class for converting between Java byte arrays and GraalVM native pointers.
 * Provides safe memory management by pinning Java byte arrays while calling native functions.
 */
public class GraalVMHelper {

    /** Private constructor to prevent instantiation of utility class. */
    private GraalVMHelper() {}

    /**
     * Functional interface for native ECRECOVER call.
     */
    @FunctionalInterface
    public interface EcrecoverNativeCall {
        /**
         * Calls the native ECRECOVER function.
         *
         * @param messageHash pointer to 32-byte message hash
         * @param signature pointer to 64-byte signature
         * @param recoveryId recovery ID (0 or 1)
         * @param outputBuffer pointer to 65-byte output buffer
         * @return 0 if recovery was successful, 1 otherwise
         */
        int call(CCharPointer messageHash, CCharPointer signature, int recoveryId, CCharPointer outputBuffer);
    }

    /**
     * Helper for calling native ECRECOVER function with byte arrays.
     *
     * @param messageHash 32-byte message hash
     * @param signature 64-byte signature (r || s)
     * @param recoveryId recovery ID (0 or 1)
     * @param outputBuffer 65-byte output buffer for recovered public key
     * @param nativeCall functional interface wrapping the native call
     * @return 0 if recovery was successful, 1 otherwise
     */
    public static int callEcrecover(
            byte[] messageHash,
            byte[] signature,
            int recoveryId,
            byte[] outputBuffer,
            EcrecoverNativeCall nativeCall) {
        try (PinnedObject pinnedHash = PinnedObject.create(messageHash);
             PinnedObject pinnedSig = PinnedObject.create(signature);
             PinnedObject pinnedOutput = PinnedObject.create(outputBuffer)) {
            return nativeCall.call(
                pinnedHash.addressOfArrayElement(0),
                pinnedSig.addressOfArrayElement(0),
                recoveryId,
                pinnedOutput.addressOfArrayElement(0)
            );
        }
    }
}
