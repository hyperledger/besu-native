package org.hyperledger.besu.nativelib.constantine;

import com.google.common.io.CharStreams;
import org.apache.tuweni.bytes.Bytes;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.io.IOException;
import java.io.InputStreamReader;
import java.util.stream.Collectors;

import static java.nio.charset.StandardCharsets.UTF_8;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class ConstantineEIP196G1AddTest {

    @Parameterized.Parameter(0)
    public String input;
    @Parameterized.Parameter(1)
    public String expectedResult;
    @Parameterized.Parameter(2)
    public String expectedGasUsed;
    @Parameterized.Parameter(3)
    public String notes;

    @Parameterized.Parameters
    public static Iterable<String[]> parameters() throws IOException {
        return CharStreams.readLines(
                        new InputStreamReader(
                                ConstantineEIP196G1AddTest.class.getResourceAsStream("/eip196_g1_add.csv"), UTF_8))
                .stream()
                .map(line -> line.split(",", 4))
                .collect(Collectors.toList());
    }

    @Test
    public void shouldCalculate() {
        if ("input".equals(input)) {
            // skip the header row
            return;
        }
        LibConstantineEIP196 constInstance = new LibConstantineEIP196();
        byte[] inputBytes = Bytes.fromHexString(this.input).toArrayUnsafe();

        byte[] result = new byte[64];
        int status = constInstance.ctt_eth_evm_bn254_g1add(result, result.length, inputBytes, inputBytes.length);

        Bytes expectedComputation = expectedResult == null ? null : Bytes.fromHexString(expectedResult);
        if (status != 0) {
            assertNotNull("Notes should not be empty", notes);
            assertNotEquals("Status should not be success", 0, status);
            assertArrayEquals("Result should be empty", new byte[64], result);
        } else {
            Bytes actualComputation = Bytes.wrap(result);
            if(actualComputation.isZero()) actualComputation = Bytes.EMPTY;
            assertEquals("Computed result should match expected result", expectedComputation, actualComputation);
            assertTrue("Notes should be empty", notes.isEmpty());
        }
    }
}