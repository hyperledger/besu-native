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

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class LibConstantineEIP2537Test {

    @Test
    public void testG1Add() {
        byte[] inputs = new byte[256];
        byte[] result = LibConstantineEIP2537.g1add(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 128", 128, result.length);
    }

    @Test
    public void testG2Add() {
        byte[] inputs = new byte[512];

        byte[] result = LibConstantineEIP2537.g2add(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 256", 256, result.length);
    }

    @Test
    public void testG1Mul() {
        byte[] inputs = new byte[160];

        byte[] result = LibConstantineEIP2537.g1mul(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 128", 128, result.length);
    }

    @Test
    public void testG2Mul() {
        byte[] inputs = new byte[288];

        byte[] result = LibConstantineEIP2537.g2mul(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 256", 256, result.length);
    }

    @Test
    public void testG1Msm() {
        byte[] inputs = new byte[160];

        byte[] result = LibConstantineEIP2537.g1msm(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 128", 128, result.length);
    }

    @Test
    public void testG2Msm() {
        byte[] inputs = new byte[288];

        byte[] result = LibConstantineEIP2537.g2msm(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 256", 256, result.length);
    }

    @Test
    public void testPairingCheck() {
        byte[] inputs = new byte[384];

        byte[] result = LibConstantineEIP2537.pairingCheck(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 32", 32, result.length);
        assertEquals("The last byte of the result should be 1", 1, result[31]);
    }

    @Test
    public void testMapFpToG1() {
        byte[] inputs = new byte[64];

        byte[] result = LibConstantineEIP2537.mapFpToG1(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 128", 128, result.length);
    }

    @Test
    public void testMapFp2ToG2() {
        byte[] inputs = new byte[128];

        byte[] result = LibConstantineEIP2537.mapFp2ToG2(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 256", 256, result.length);
    }
}
