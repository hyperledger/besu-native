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
package org.hyperledger.besu.nativelib.secp256r1;

import java.util.Arrays;
import java.util.Objects;

public class Signature {
    private final byte[] r;
    private final byte[] s;
    private final byte v;

    public Signature(byte[] r, byte[] s, byte v) {
        this.r = r;
        this.s = s;
        this.v = v;
    }

    public byte[] getR() {
        return r;
    }

    public byte[] getS() {
        return s;
    }

    public byte getV() {
        return v;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        Signature signature = (Signature) o;
        return v == signature.v && Arrays.equals(r, signature.r) && Arrays.equals(s, signature.s);
    }

    @Override
    public int hashCode() {
        int result = Objects.hash(v);
        result = 31 * result + Arrays.hashCode(r);
        result = 31 * result + Arrays.hashCode(s);
        return result;
    }

    @Override
    public String toString() {
        return "Signature{" +
                "r=" + Arrays.toString(r) +
                ", s=" + Arrays.toString(s) +
                ", v=" + v +
                '}';
    }
}
