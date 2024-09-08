package org.hyperledger.besu.nativelib.constantine;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class LibConstantineEIP2537Test {

    @Test
    public void testG1Add() {
        byte[] inputs = new byte[192];  // G1Add inputs for BLS12-381 should be 192 bytes

        byte[] result = LibConstantineEIP2537.g1add(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 96", 96, result.length);
    }

    @Test
    public void testG2Add() {
        byte[] inputs = new byte[384];  // G2Add inputs for BLS12-381 should be 384 bytes

        byte[] result = LibConstantineEIP2537.g2add(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 192", 192, result.length);
    }

    @Test
    public void testG1Mul() {
        byte[] inputs = new byte[192];  // G1Mul inputs for BLS12-381 should be 192 bytes

        byte[] result = LibConstantineEIP2537.g1mul(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 96", 96, result.length);
    }

    @Test
    public void testG2Mul() {
        byte[] inputs = new byte[384];  // G2Mul inputs for BLS12-381 should be 384 bytes

        byte[] result = LibConstantineEIP2537.g2mul(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 192", 192, result.length);
    }

    @Test
    public void testG1Msm() {
        byte[] inputs = new byte[192];  // G1MSM inputs for BLS12-381 should be 192 bytes

        byte[] result = LibConstantineEIP2537.g1msm(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 96", 96, result.length);
    }

    @Test
    public void testG2Msm() {
        byte[] inputs = new byte[384];  // G2MSM inputs for BLS12-381 should be 384 bytes

        byte[] result = LibConstantineEIP2537.g2msm(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 192", 192, result.length);
    }

    @Test
    public void testPairingCheck() {
        byte[] inputs = new byte[0];  // PairingCheck may accept an empty input

        byte[] result = LibConstantineEIP2537.pairingCheck(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 32", 32, result.length);
        assertEquals("The last byte of the result should be 1", 1, result[31]);
    }

    @Test
    public void testMapFpToG1() {
        byte[] inputs = new byte[48];  // Fp to G1 inputs for BLS12-381 should be 48 bytes

        byte[] result = LibConstantineEIP2537.mapFpToG1(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 96", 96, result.length);
    }

    @Test
    public void testMapFp2ToG2() {
        byte[] inputs = new byte[96];  // Fp2 to G2 inputs for BLS12-381 should be 96 bytes

        byte[] result = LibConstantineEIP2537.mapFp2ToG2(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 192", 192, result.length);
    }
}
