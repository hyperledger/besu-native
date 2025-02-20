package org.hyperledger.besu.nativelib.constantine;

import org.apache.tuweni.bytes.Bytes;
import org.junit.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertThrows;

public class LibConstantineKeccak256Test {

    @Test
    public void testKeccakNonimalCase() {
        final byte[] inputs = "testKeccak256".getBytes(StandardCharsets.UTF_8);
        final byte[] result = LibConstantineKeccak256.keccak256(inputs);
        assertEquals(Bytes.wrap(result), Bytes.fromHexString("0xfe8baa653979909c621153b53c973bab3832768b5e77896a5b5944d20d48c7a6"));
    }


}
