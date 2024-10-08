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
