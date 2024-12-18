package org.hyperledger.besu.nativelib.constantine;

import org.junit.Test;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class LibConstantineVerkleTest {

    @Test
    public void testCommit() {
        byte[] inputs = new byte[128];

        byte[] result = LibConstantineEIP196.add(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 128", 128, result.length);
    }

    @Test
    public void testProve() {
        byte[] inputs = new byte[96];

        byte[] result = LibConstantineEIP196.mul(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 128", 128, result.length);
    }

    @Test
    public void testVerify() {
        byte[] inputs = new byte[0];

        byte[] result = LibConstantineEIP196.pairingCheck(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 128", 128, result.length);
    }

    @Test
    public void testMultiProve() {
        byte[] inputs = new byte[0];

        byte[] result = LibConstantineEIP196.pairingCheck(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 128", 128, result.length);
    }

    @Test
    public void testMultiVerify() {
        byte[] inputs = new byte[0];

        byte[] result = LibConstantineEIP196.pairingCheck(inputs);
        assertNotNull("Result array should not be null", result);
        assertEquals("Result array length should be 128", 128, result.length);
        assertEquals("The last byte of the result should be 1", 1, result[31]);
    }
}
