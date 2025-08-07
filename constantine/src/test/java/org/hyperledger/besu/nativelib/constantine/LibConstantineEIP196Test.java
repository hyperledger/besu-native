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
package org.hyperledger.besu.nativelib.constantine;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class LibConstantineEIP196Test {

    @Test
    public void testG1Add() {
        byte[] inputs = new byte[128];

        byte[] result = LibConstantineEIP196.add(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 64", 64, result.length);
    }

    @Test
    public void testG1Mul() {
        byte[] inputs = new byte[96];

        byte[] result = LibConstantineEIP196.mul(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 64", 64, result.length);
    }

    @Test
    public void testPairingCheck() {
        byte[] inputs = new byte[0];

        byte[] result = LibConstantineEIP196.pairingCheck(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 32", 32, result.length);
        assertEquals("The last byte of the result should be 1", 1, result[31]);
    }
}
