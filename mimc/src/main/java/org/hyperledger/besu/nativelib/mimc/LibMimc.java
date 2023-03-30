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
package org.hyperledger.besu.nativelib.mimc;

import com.sun.jna.Memory;
import com.sun.jna.Native;
import com.sun.jna.Pointer;

/**
 * Java interface to mimc
 */
public class LibMimc {

    @SuppressWarnings("WeakerAccess")
    public static final boolean ENABLED;

    static {
        boolean enabled;
        try {
            Native.register(LibMimc.class, "mimc_jni");
            enabled = true;
        } catch (final Throwable t) {
            t.printStackTrace();
            enabled = false;
        }
        ENABLED = enabled;
    }

    public static byte[] mimc(byte[] input){
        Pointer inputPointer = new Memory(input.length);
        inputPointer.write(0, input, 0, input.length);

        Pointer output = compute(inputPointer, input.length);

        byte[] hash = output.getByteArray(0, 32);

        Native.free(Pointer.nativeValue(output));

        return hash;
    }

    public static native Pointer compute(
            Pointer input , int i_len);
}