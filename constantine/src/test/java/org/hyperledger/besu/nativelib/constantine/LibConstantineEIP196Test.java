package org.hyperledger.besu.nativelib.constantine;

import org.junit.Before;
import org.junit.Test;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

public class LibConstantineEIP196Test {
    private LibConstantineEIP196 constInstance;

    @Before
    public void setUp() {
        constInstance = new LibConstantineEIP196();
    }

    @Test
    public void testG1Add() {
        byte[] r = new byte[64];
        byte[] inputs = new byte[128];
        int status = constInstance.ctt_eth_evm_bn254_g1add(r, r.length, inputs, inputs.length);
        assertEquals("Status should be cttEVM_Success", 0, status);
        assertNotNull("Result array should not be null", r);
    }

    @Test
    public void testG1Mul() {
        byte[] r = new byte[64];
        byte[] inputs = new byte[96];
        int status = constInstance.ctt_eth_evm_bn254_g1mul(r, r.length, inputs, inputs.length);
        assertEquals("Status should be cttEVM_Success", 0, status);
        assertNotNull("Result array should not be null", r);
    }

    @Test
    public void testPairingCheck() {
        byte[] r = new byte[32];
        byte[] inputs = new byte[256];
        int status = constInstance.ctt_eth_evm_bn254_pairingCheck(r, r.length, inputs, inputs.length);
        assertEquals("Status should be cttEVM_Success", 0, status);
        assertNotNull("Result array should not be null", r);
    }
}
