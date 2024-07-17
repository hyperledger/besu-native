package org.hyperledger.besu.nativelib.constantine;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

public class LibConstantineEIP196Test {
    private LibConstantineEIP196 constInstance;

    @Before
    public void setUp() {
        LibConstantineEIP196.loadNativeLibrary();
        constInstance = new LibConstantineEIP196();
    }

    @Test
    public void testG1Add() {
        byte[] inputs = new byte[128];

        byte[] result = constInstance.add(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 64", 64, result.length);
    }

    @Test
    public void testG1Mul() {
        byte[] inputs = new byte[96];

        byte[] result = constInstance.mul(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 64", 64, result.length);
    }

    @Test
    public void testPairingCheck() {
        byte[] inputs = new byte[0];  // Empty input

        byte[] result = constInstance.pairingCheck(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 32", 32, result.length);
        assertEquals("The last byte of the result should be 1", 1, result[31]);
    }
}