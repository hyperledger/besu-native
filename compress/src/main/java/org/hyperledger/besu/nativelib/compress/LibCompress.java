/*
 * Copyright Hyperledger Besu Contributors
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
package org.hyperledger.besu.nativelib.compress;

import com.sun.jna.Native;

/**
 * Java interface to compress
 */
public class LibCompress {

    @SuppressWarnings("WeakerAccess")
    public static final boolean ENABLED;

    static {
        boolean enabled;
        try {
            Native.register(LibCompress.class, "compress_jni");

            // TODO don't know how to manage resources well (in the java project sense of the term)
            // -- "compressor_dict.bin" should match 
            // the version used in Linea.

            if (!Init("compressor_dict.bin")) {
                throw new RuntimeException(Error());
            }
            enabled = true;
        } catch (final Throwable t) {
            t.printStackTrace();
            enabled = false;
        }
        ENABLED = enabled;
    }

    public static native boolean Init(String dictPath);
    
    public static native int CompressedSize(
            byte[] i, int i_len);

    public static native String Error();


}